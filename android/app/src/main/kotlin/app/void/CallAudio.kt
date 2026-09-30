package app.void

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import androidx.core.content.ContextCompat
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Captures, encodes, sends, receives, decodes and plays one call's audio.
 *
 * ## Why the codec is here and not in Rust
 *
 * `void-crypto` has exactly two third-party dependencies and `check_deps.sh`
 * fails the build on a third (NFR-SEC-07). Linking libopus would mean C in the
 * workspace, `unsafe` outside the two FFI crates, and an exemption in that
 * check — for a codec Android has shipped in `MediaCodec` since API 21. So the
 * core stays codec-agnostic and moves opaque bytes, and this file is the only
 * place on Android that knows what those bytes are.
 *
 * ## Constant bitrate, deliberately
 *
 * The encoder runs at a fixed bitrate with no voice-activity detection. A
 * variable-rate codec makes packet sizes track the shape of speech, which
 * leaks phonetics to anyone counting bytes — a published attack, not a
 * hypothetical one. The core pads every frame to one size regardless;
 * configuring the encoder to match means that padding is not also wasting
 * bandwidth on a circuit that has none to spare.
 *
 * ## Three threads
 *
 * - Capture reads the microphone one 20 ms frame at a time, encodes it, and
 *   queues the packet — at most 200 ms of them; older ones are dropped.
 * - A paced sender sends exactly one frame every 20 ms: the next packet, or
 *   silence if there is none or the microphone is muted. The cadence never
 *   varies, so the traffic shape does not reveal who is talking, when, or
 *   whether they are muted.
 * - A receiver blocks on the network, decodes, and plays — and decides when the
 *   call has dropped: the connection closed, or ten seconds passed with nothing
 *   authenticated arriving.
 *
 * Teardown is [stop]: close the media so a blocked receive wakes, join all
 * three threads, release the codecs and audio devices, then free the media.
 */
class CallAudio(
    context: Context,
    private val media: CallMedia,
) {
    /** 20 ms frames at 16 kHz mono — wideband speech, which is as much as a
     *  circuit this slow carries without the delay growing further. */
    private val sampleRate = 16_000
    private val bitRate = 16_000
    private val frameMs = VoidCore.callFrameMs().toInt()
    private val samplesPerFrame = sampleRate * frameMs / 1000
    private val frameBytes = samplesPerFrame * 2
    private val maxPayload = VoidCore.callPayloadLen()

    private val appContext = context.applicationContext
    private val audioManager = context.getSystemService(AudioManager::class.java)
    private var previousAudioMode = AudioManager.MODE_NORMAL

    /** Whether the microphone is muted. Muting sends silence on the same cadence. */
    @Volatile var muted: Boolean = false

    /** Called once, from the receiving thread, on the first authenticated frame. Set before [start]. */
    var onConnected: (() -> Unit)? = null

    /**
     * Called once, from an audio thread, when the call is over from this end's
     * point of view: `true` if the connection closed — nearly always the other
     * end hanging up, whose relayed "ended" arrives seconds later — `false` if
     * it stalled, open but carrying nothing authenticated for ten seconds, or
     * the audio failed. Set before [start].
     */
    var onDropped: ((connectionClosed: Boolean) -> Unit)? = null

    @Volatile private var running = false
    private val connected = AtomicBoolean(false)
    private val stopped = AtomicBoolean(false)
    private val encoded = ArrayBlockingQueue<ByteArray>(MAX_QUEUED_PACKETS)

    private var record: AudioRecord? = null
    private var track: AudioTrack? = null
    private var echoCanceler: AcousticEchoCanceler? = null
    private var encoder: MediaCodec? = null
    private var decoder: MediaCodec? = null
    private val threads = mutableListOf<Thread>()

    /** What [track] plays: the decoder's output, once it says what that is. */
    private var playbackRate = 16_000
    private var playbackChannels = 1

    /**
     * Start capture, playback, and the network threads. `RECORD_AUDIO` must
     * already be granted — asking mid-call is the wrong moment.
     */
    fun start() {
        if (ContextCompat.checkSelfPermission(appContext, Manifest.permission.RECORD_AUDIO) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            throw SecurityException("the microphone permission has not been granted")
        }
        previousAudioMode = audioManager.mode
        audioManager.mode = AudioManager.MODE_IN_COMMUNICATION

        val minRecord = AudioRecord.getMinBufferSize(sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val recorder = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(minRecord, frameBytes * 4),
        )
        record = recorder
        if (recorder.state != AudioRecord.STATE_INITIALIZED) throw IllegalStateException("microphone unavailable")
        // Without echo cancellation the other person hears themselves a second
        // later, which on a line with this much delay is unusable.
        if (AcousticEchoCanceler.isAvailable()) {
            echoCanceler = AcousticEchoCanceler.create(recorder.audioSessionId)?.apply { enabled = true }
        }

        track = buildTrack(sampleRate, 1)

        encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).apply {
            configure(encoderFormat(), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            start()
        }
        decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).apply {
            configure(decoderFormat(), null, null, 0)
            start()
        }

        running = true
        recorder.startRecording()
        track?.play()

        threads += thread(name = "void-call-capture", priority = Thread.MAX_PRIORITY) { guarded { captureLoop() } }
        threads += thread(name = "void-call-send", priority = Thread.MAX_PRIORITY) { guarded { sendLoop() } }
        threads += thread(name = "void-call-receive", priority = Thread.MAX_PRIORITY) { guarded { receiveLoop() } }
    }

    /**
     * Hang up the audio. Returns at once; the teardown — join the threads,
     * release the codecs and devices, free the media — finishes on its own
     * thread, in that order. Safe to call more than once.
     */
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        running = false
        media.close()
        val joining = threads.toList()
        thread(name = "void-call-teardown") {
            // A blocked receive wakes within about a tenth of a second of the
            // close, capture within one frame, the sender within one frame.
            joining.forEach { it.join(3_000) }
            runCatching { record?.stop() }
            runCatching { track?.stop() }
            runCatching { echoCanceler?.release() }
            runCatching { record?.release() }
            runCatching { track?.release() }
            runCatching { encoder?.stop() }
            runCatching { decoder?.stop() }
            runCatching { encoder?.release() }
            runCatching { decoder?.release() }
            runCatching { audioManager.mode = previousAudioMode }
            media.free()
        }
    }

    /** An exception on an audio thread ends the call rather than the process. */
    private inline fun guarded(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            dropped(connectionClosed = false)
        }
    }

    /**
     * A playback track for PCM at `rate` Hz and `channels` channels, holding at
     * most [MAX_QUEUED_PLAYBACK_FRAMES] of it: the playback cap. Tor delivers
     * late packets in clumps (runs of half a second and more are in the
     * measurements); playing a clump in full would add its length to every
     * word that followed.
     */
    private fun buildTrack(rate: Int, channels: Int): AudioTrack {
        val mask = if (channels == 2) AudioFormat.CHANNEL_OUT_STEREO else AudioFormat.CHANNEL_OUT_MONO
        val minTrack = AudioTrack.getMinBufferSize(rate, mask, AudioFormat.ENCODING_PCM_16BIT)
        val bytesPerFrame = rate * frameMs / 1000 * 2 * channels
        return AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build(),
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(rate)
                    .setChannelMask(mask)
                    .build(),
            )
            .setBufferSizeInBytes(maxOf(minTrack, bytesPerFrame * MAX_QUEUED_PLAYBACK_FRAMES))
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()
    }

    /**
     * Follow the decoder to whatever it actually produces. Android's Opus
     * decoder always outputs 48 kHz, whatever rate it was configured with;
     * played into a 16 kHz track that was three times too slow, and overran the
     * playback cap constantly. Only ever called on the receiving thread, which
     * is the only user of [track] until teardown.
     */
    private fun retune(format: MediaFormat) {
        val rate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE)
        val channels = if (format.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) {
            format.getInteger(MediaFormat.KEY_CHANNEL_COUNT)
        } else {
            1
        }
        if (rate == playbackRate && channels == playbackChannels) return
        val replacement = buildTrack(rate, channels)
        track?.let { old ->
            runCatching { old.stop() }
            old.release()
        }
        replacement.play()
        track = replacement
        playbackRate = rate
        playbackChannels = channels
    }

    private fun encoderFormat(): MediaFormat =
        MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, sampleRate, 1).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, bitRate)
            // CBR, not VBR — see the class docs. This is a privacy setting
            // wearing an audio setting's clothes.
            setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
            setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, frameBytes)
        }

    /**
     * The decoder needs Opus's identification header and its two delays —
     * `csd-0`, `csd-1`, `csd-2` in MediaCodec's terms — and never got them,
     * so it could not decode anything. Both ends run the same encoder settings,
     * so the header is built here rather than sent.
     */
    private fun decoderFormat(): MediaFormat =
        MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, sampleRate, 1).apply {
            setByteBuffer("csd-0", ByteBuffer.wrap(opusHead()))
            setByteBuffer("csd-1", ByteBuffer.wrap(littleEndian(PRE_SKIP_NS)))
            setByteBuffer("csd-2", ByteBuffer.wrap(littleEndian(SEEK_PRE_ROLL_NS)))
        }

    /** RFC 7845's identification header for one channel at 16 kHz. */
    private fun opusHead(): ByteArray {
        val head = ByteArray(19)
        "OpusHead".toByteArray(Charsets.US_ASCII).copyInto(head)
        head[8] = 1 // version
        head[9] = 1 // channels
        head[10] = (PRE_SKIP_SAMPLES and 0xff).toByte()
        head[11] = (PRE_SKIP_SAMPLES shr 8).toByte()
        head[12] = (sampleRate and 0xff).toByte()
        head[13] = (sampleRate shr 8 and 0xff).toByte()
        head[14] = (sampleRate shr 16 and 0xff).toByte()
        head[15] = (sampleRate shr 24 and 0xff).toByte()
        // Output gain 0 and mapping family 0 (mono or stereo) are the zeros left.
        return head
    }

    private fun littleEndian(value: Long): ByteArray = ByteArray(8) { i -> (value shr (8 * i)).toByte() }

    // --- capture ---------------------------------------------------------------

    private fun captureLoop() {
        val recorder = record ?: return
        val codec = encoder ?: return
        val pcm = ByteArray(frameBytes)
        val info = MediaCodec.BufferInfo()
        while (running) {
            // Blocks for one frame's worth of audio, which is what paces this
            // loop at real time.
            var read = 0
            while (read < frameBytes && running) {
                val n = recorder.read(pcm, read, frameBytes - read)
                if (n <= 0) break
                read += n
            }
            if (!running || read < frameBytes) continue
            if (muted) {
                // Dropped, not kept: unmuting must not send what was said while muted.
                encoded.clear()
                continue
            }
            feed(codec, pcm, frameBytes)
            drainEncoder(codec, info)
        }
    }

    private fun feed(codec: MediaCodec, data: ByteArray, length: Int) {
        val index = codec.dequeueInputBuffer(CODEC_TIMEOUT_US)
        if (index < 0) return
        val buffer = codec.getInputBuffer(index) ?: return
        buffer.clear()
        buffer.put(data, 0, length)
        codec.queueInputBuffer(index, 0, length, System.nanoTime() / 1000, 0)
    }

    /**
     * Take every packet the encoder has ready, not just one — one per frame
     * fell behind whenever the codec produced two at once — and never send
     * its setup data as if it were audio.
     */
    private fun drainEncoder(codec: MediaCodec, info: MediaCodec.BufferInfo) {
        while (true) {
            val index = codec.dequeueOutputBuffer(info, 0)
            if (index < 0) return
            val buffer = codec.getOutputBuffer(index)
            val isConfig = info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0
            if (buffer != null && !isConfig && info.size > 0) {
                val packet = ByteArray(info.size)
                buffer.position(info.offset)
                buffer.get(packet)
                // Anything larger than the core carries is dropped rather than
                // cut: half an Opus packet is noise, not quieter speech.
                if (packet.size <= maxPayload) {
                    while (!encoded.offer(packet)) encoded.poll()
                }
            }
            codec.releaseOutputBuffer(index, false)
        }
    }

    // --- sending ---------------------------------------------------------------

    /** One frame every [frameMs], on a clock that does not drift. */
    private fun sendLoop() {
        val frameNanos = frameMs * 1_000_000L
        var deadline = System.nanoTime()
        val silence = ByteArray(0)
        while (running) {
            val packet = if (muted) null else encoded.poll()
            if (!media.send(packet ?: silence)) {
                // Refused because the connection is gone: whichever of the two
                // threads notices first, a closed connection means the same.
                dropped(connectionClosed = true)
                return
            }
            deadline += frameNanos
            val now = System.nanoTime()
            if (deadline > now) {
                val wait = deadline - now
                Thread.sleep(wait / 1_000_000, (wait % 1_000_000).toInt())
            } else if (now - deadline > 10 * frameNanos) {
                // Far behind: resynchronise instead of sending a burst.
                deadline = now
            }
        }
    }

    // --- receiving ---------------------------------------------------------------

    private fun receiveLoop() {
        val codec = decoder ?: return
        val info = MediaCodec.BufferInfo()
        var lastHeard = System.nanoTime()
        while (running) {
            when (val received = media.receive()) {
                is MediaReceive.Audio -> {
                    lastHeard = System.nanoTime()
                    announceConnected()
                    feed(codec, received.frame, received.frame.size)
                    drainDecoder(codec, info)
                }
                MediaReceive.Silence -> {
                    lastHeard = System.nanoTime()
                    announceConnected()
                }
                MediaReceive.Nothing -> {
                    if (System.nanoTime() - lastHeard > TimeUnit.SECONDS.toNanos(DROP_AFTER_SECONDS)) {
                        dropped(connectionClosed = false)
                        return
                    }
                }
                MediaReceive.Closed -> {
                    if (running) dropped(connectionClosed = true)
                    return
                }
            }
        }
    }

    private fun drainDecoder(codec: MediaCodec, info: MediaCodec.BufferInfo) {
        while (true) {
            val index = codec.dequeueOutputBuffer(info, CODEC_TIMEOUT_US)
            if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                retune(codec.outputFormat)
                continue
            }
            if (index < 0) return
            val buffer = codec.getOutputBuffer(index)
            val out = track
            if (buffer != null && out != null && info.size > 0) {
                val pcm = ByteArray(info.size)
                buffer.position(info.offset)
                buffer.get(pcm)
                play(out, pcm)
            }
            codec.releaseOutputBuffer(index, false)
        }
    }

    /**
     * Play without ever waiting. If the track's buffer — [MAX_QUEUED_PLAYBACK_FRAMES]
     * of audio — is full, the oldest audio is dropped rather than letting the
     * delay grow for the rest of the call.
     */
    private fun play(out: AudioTrack, pcm: ByteArray) {
        val written = out.write(pcm, 0, pcm.size, AudioTrack.WRITE_NON_BLOCKING)
        if (written in 0 until pcm.size) {
            out.pause()
            out.flush()
            out.play()
            out.write(pcm, 0, pcm.size, AudioTrack.WRITE_NON_BLOCKING)
        }
    }

    private fun announceConnected() {
        if (connected.compareAndSet(false, true)) onConnected?.invoke()
    }

    private fun dropped(connectionClosed: Boolean) {
        val wasRunning = running
        running = false
        media.close()
        if (wasRunning && !stopped.get()) onDropped?.invoke(connectionClosed)
    }

    private companion object {
        /** 200 ms of encoded audio waiting for the sender, at most. */
        const val MAX_QUEUED_PACKETS = 10

        /** 400 ms of received audio waiting to be played, at most. */
        const val MAX_QUEUED_PLAYBACK_FRAMES = 20

        const val CODEC_TIMEOUT_US = 5_000L
        const val DROP_AFTER_SECONDS = 10L

        /** The encoder's lookahead, as Opus defines it: 312 samples at 48 kHz, 6.5 ms. */
        const val PRE_SKIP_SAMPLES = 312
        const val PRE_SKIP_NS = 6_500_000L

        /** RFC 7845's recommended seek pre-roll: 80 ms. */
        const val SEEK_PRE_ROLL_NS = 80_000_000L
    }
}
