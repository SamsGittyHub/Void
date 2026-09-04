package app.void

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioManager
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaRecorder
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * Captures and plays Opus frames for one call.
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
 * ## Mute
 *
 * [transmitting] gates the microphone, not the emission. Silence frames go out
 * on the same cadence whether or not anyone is speaking, so the traffic shape
 * of a call does not reveal who is talking, when, or whether they are muted.
 */
class CallAudio(
    private val mediaHandle: Long,
) {
    /** 20 ms frames at 16 kHz mono — wideband speech, which is as much as a
     *  circuit this slow carries without the jitter buffer growing further. */
    private val sampleRate = 16_000
    private val bitRate = 16_000
    private val frameMs = VoidCore.callFrameMs().toInt()
    private val samplesPerFrame = sampleRate * frameMs / 1000

    /** Whether the microphone is open. Muting sets this false; silence frames
     *  still go out either way, so muting changes what the other person hears
     *  and nothing about what the network sees. */
    @Volatile var transmitting: Boolean = true

    @Volatile private var running = false
    private var record: AudioRecord? = null
    private var track: AudioTrack? = null
    private var encoder: MediaCodec? = null
    private var decoder: MediaCodec? = null
    private var captureThread: Thread? = null
    private var receiveThread: Thread? = null

    /**
     * Start capture and playback. Requires `RECORD_AUDIO`, which the caller
     * must already have been granted — this throws rather than prompting,
     * because a permission dialog mid-call is the wrong place to ask.
     */
    fun start() {
        val minBuffer = AudioRecord.getMinBufferSize(
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
        )
        record = AudioRecord(
            MediaRecorder.AudioSource.VOICE_COMMUNICATION,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            maxOf(minBuffer, samplesPerFrame * 4),
        )

        track = AudioTrack.Builder()
            .setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build()
            )
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(sampleRate)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .build()
            )
            .setTransferMode(AudioTrack.MODE_STREAM)
            .build()

        encoder = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).apply {
            configure(opusFormat(), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            start()
        }
        decoder = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_AUDIO_OPUS).apply {
            configure(opusFormat(), null, null, 0)
            start()
        }

        running = true
        record?.startRecording()
        track?.play()

        captureThread = thread(name = "void-call-capture", priority = Thread.MAX_PRIORITY) {
            captureLoop()
        }
        receiveThread = thread(name = "void-call-receive", priority = Thread.MAX_PRIORITY) {
            receiveLoop()
        }
    }

    fun stop() {
        running = false
        captureThread?.join(500)
        receiveThread?.join(500)
        runCatching { record?.stop() }
        runCatching { track?.stop() }
        record?.release()
        track?.release()
        runCatching { encoder?.stop() }
        runCatching { decoder?.stop() }
        encoder?.release()
        decoder?.release()
        record = null
        track = null
        encoder = null
        decoder = null
        VoidCore.callMediaFree(mediaHandle)
    }

    private fun opusFormat(): MediaFormat =
        MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_OPUS, sampleRate, 1).apply {
            setInteger(MediaFormat.KEY_BIT_RATE, bitRate)
            // CBR, not VBR — see the class docs. This is a privacy setting
            // wearing an audio setting's clothes.
            setInteger(
                MediaFormat.KEY_BITRATE_MODE,
                MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR,
            )
            setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, samplesPerFrame * 2)
        }

    /**
     * Reads the microphone, encodes, and sends one frame every [frameMs].
     *
     * When not transmitting it sends an empty frame, which the core turns into
     * a silence frame of exactly the same wire size. The cadence never varies.
     */
    private fun captureLoop() {
        val pcm = ByteArray(samplesPerFrame * 2)
        val silence = ByteArray(0)
        val codec = encoder ?: return
        val info = MediaCodec.BufferInfo()

        while (running) {
            if (transmitting) {
                val read = record?.read(pcm, 0, pcm.size) ?: 0
                if (read > 0) {
                    feed(codec, pcm, read)
                }
                val encoded = drain(codec, info)
                VoidCore.callMediaSend(mediaHandle, encoded ?: silence)
            } else {
                // Drain whatever the microphone produced so the buffer does not
                // back up, then send silence rather than it.
                record?.read(pcm, 0, pcm.size)
                VoidCore.callMediaSend(mediaHandle, silence)
                Thread.sleep(frameMs.toLong())
            }
        }
    }

    private fun feed(codec: MediaCodec, pcm: ByteArray, length: Int) {
        val index = codec.dequeueInputBuffer(10_000)
        if (index < 0) return
        val buffer: ByteBuffer = codec.getInputBuffer(index) ?: return
        buffer.clear()
        buffer.put(pcm, 0, length)
        codec.queueInputBuffer(index, 0, length, System.nanoTime() / 1000, 0)
    }

    private fun drain(codec: MediaCodec, info: MediaCodec.BufferInfo): ByteArray? {
        val index = codec.dequeueOutputBuffer(info, 10_000)
        if (index < 0) return null
        val buffer = codec.getOutputBuffer(index) ?: return null
        val out = ByteArray(info.size)
        buffer.get(out)
        codec.releaseOutputBuffer(index, false)
        // Anything larger than the core will carry is dropped rather than
        // truncated: half an Opus frame is noise, not quieter speech.
        return if (out.size <= VoidCore.callPayloadLen()) out else null
    }

    /** Receives frames, decodes, and plays them. */
    private fun receiveLoop() {
        val codec = decoder ?: return
        val info = MediaCodec.BufferInfo()
        while (running) {
            val frame = VoidCore.callMediaRecv(mediaHandle)
            if (frame.isEmpty()) continue // silence, replay, or a bad frame
            feed(codec, frame, frame.size)
            val pcm = drain(codec, info) ?: continue
            track?.write(pcm, 0, pcm.size)
        }
    }
}
