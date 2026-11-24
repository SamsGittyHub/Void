package app.void

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Matrix
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Range
import android.util.Size
import android.view.Surface
import android.view.TextureView
import java.nio.ByteBuffer
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** What the other end's video is doing, for the call screen. */
data class RemoteVideoState(val started: Boolean = false, val cameraOff: Boolean = false)

/**
 * Captures, encodes, sends, receives, decodes and shows one video call's
 * pictures — the Kotlin mirror of `ios/Void/CallVideo.swift` (D-033). The
 * audio is [CallAudio]'s, unchanged: a video call is a voice call whose frames
 * also carry a slice of video.
 *
 * ## The codec is the phone's
 *
 * For the reason [CallAudio] gives for Opus: Android ships H.264, usually in
 * hardware, and the core moves opaque units. The two apps agree between
 * themselves on what is in them — H.264 Annex B, Baseline, the parameter sets
 * in front of every keyframe — and this is the only Kotlin that knows.
 *
 * ## Sized for the lane, not the camera
 *
 * The lane is 224 kbit/s and constant. The encoder is asked for about two
 * thirds of that at 15 frames a second, at the smallest 4:3 size the camera
 * offers from 320×240 up: enough for a face, with room for a keyframe to drain.
 * What it produces beyond the lane is dropped by the core and answered with a
 * keyframe — queued video is delay that never goes away.
 *
 * ## Upright, unmirrored
 *
 * Frames go out the way the sensor delivers them, with the quarter turns that
 * make them upright alongside ([VideoUnit.rotation]); the receiving app turns
 * them. They are never mirrored: the other person sees what anyone opposite
 * would. Only the local preview is a mirror.
 */
class CallVideo(private val context: Context, private val media: CallMedia) {
    /** Called on the main thread when the other end's video changes state. */
    var onRemoteState: ((RemoteVideoState) -> Unit)? = null

    /** Called on the main thread with the quarter turns the other end's frames ask for. */
    var onRemoteRotation: ((Int) -> Unit)? = null

    /** Counts, for the call screen's details. */
    class Stats {
        @Volatile var encoded = 0
        @Volatile var sent = 0
        @Volatile var dropped = 0
        @Volatile var received = 0
        @Volatile var shown = 0
    }

    val stats = Stats()

    @Volatile var isCameraOn = false
        private set

    @Volatile var isFrontCamera = true
        private set

    private val running = AtomicBoolean(true)
    private val main = Handler(context.mainLooper)
    private val cameraThread = HandlerThread("void-video-camera").apply { start() }
    private val cameraHandler = Handler(cameraThread.looper)
    private val lock = Any()

    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var encoder: MediaCodec? = null
    private var encoderSurface: Surface? = null
    private var encoderThread: Thread? = null
    private var parameterSets: ByteArray? = null
    private var sensorTurns = 0
    private var previewSurface: Surface? = null
    private val started = System.nanoTime()

    private var decoder: MediaCodec? = null
    private var remoteSurface: Surface? = null
    private var decoderThread: Thread? = null
    private val incoming = LinkedBlockingQueue<VideoUnit>(MAX_WAITING_UNITS)
    private var decoderSps: ByteArray? = null
    private var decoderPps: ByteArray? = null
    private var remote = RemoteVideoState()
    private var remoteTurns = 0

    /** Start the decoder, and — if allowed — the camera and encoder. */
    fun start(cameraAllowed: Boolean) {
        decoderThread = Thread({ decodeLoop() }, "void-video-decode").apply { start() }
        setCamera(cameraAllowed)
    }

    /** Stop everything: camera, encoder, decoder. Safe twice. */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        stopCamera()
        decoderThread?.interrupt()
        decoderThread?.join(1_000)
        synchronized(lock) {
            runCatching { decoder?.stop() }
            runCatching { decoder?.release() }
            decoder = null
        }
        cameraThread.quitSafely()
    }

    /** Turn the camera on or off. Off, nothing is captured; the wire is the same size either way. */
    fun setCamera(on: Boolean) {
        isCameraOn = on
        media.setCamera(on)
        if (on) startCamera() else stopCamera()
    }

    /** Switch between the front and back cameras. */
    fun flipCamera() {
        isFrontCamera = !isFrontCamera
        if (isCameraOn) {
            stopCamera()
            startCamera()
        }
    }

    /** Where to draw the local preview, once its view exists. */
    fun setPreviewSurface(texture: SurfaceTexture?) {
        previewSurface = texture?.let { Surface(it) }
        if (isCameraOn) {
            stopCamera()
            startCamera()
        }
    }

    /** Where to draw the other end's picture, once its view exists. */
    fun setRemoteSurface(texture: SurfaceTexture?) {
        synchronized(lock) {
            remoteSurface = texture?.let { Surface(it) }
            // A decoder bound to a surface that went away is useless; start
            // again from the next keyframe on the new one.
            runCatching { decoder?.stop() }
            runCatching { decoder?.release() }
            decoder = null
        }
    }

    // --- the camera --------------------------------------------------------------

    @SuppressLint("MissingPermission") // Checked by the caller when the call was chosen.
    private fun startCamera() {
        val manager = context.getSystemService(CameraManager::class.java) ?: return
        val facing = if (isFrontCamera) CameraCharacteristics.LENS_FACING_FRONT else CameraCharacteristics.LENS_FACING_BACK
        val id = manager.cameraIdList.firstOrNull {
            manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == facing
        } ?: manager.cameraIdList.firstOrNull() ?: return
        val characteristics = manager.getCameraCharacteristics(id)
        sensorTurns = ((characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0) / 90) and 3
        val size = pickSize(characteristics)
        val encoder = runCatching { makeEncoder(size) }.getOrNull() ?: return
        synchronized(lock) {
            this.encoder = encoder
            encoderSurface = encoder.createInputSurface()
        }
        encoder.start()
        encoderThread = Thread({ encodeLoop(encoder) }, "void-video-encode").apply { start() }

        runCatching {
            manager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    val targets = listOfNotNull(encoderSurface, previewSurface)
                    @Suppress("DEPRECATION")
                    device.createCaptureSession(targets, object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(configured: CameraCaptureSession) {
                            session = configured
                            val request = device.createCaptureRequest(CameraDevice.TEMPLATE_RECORD).apply {
                                targets.forEach { addTarget(it) }
                                fpsRange(characteristics)?.let { set(CaptureRequest.CONTROL_AE_TARGET_FPS_RANGE, it) }
                            }
                            runCatching { configured.setRepeatingRequest(request.build(), null, cameraHandler) }
                        }

                        override fun onConfigureFailed(failed: CameraCaptureSession) {
                            stopCamera()
                        }
                    }, cameraHandler)
                }

                override fun onDisconnected(device: CameraDevice) = device.close()
                override fun onError(device: CameraDevice, error: Int) = device.close()
            }, cameraHandler)
        }
    }

    private fun stopCamera() {
        runCatching { session?.close() }
        session = null
        runCatching { camera?.close() }
        camera = null
        val (codec, surface) = synchronized(lock) {
            val pair = encoder to encoderSurface
            encoder = null
            encoderSurface = null
            pair
        }
        encoderThread?.interrupt()
        encoderThread?.join(1_000)
        encoderThread = null
        runCatching { codec?.stop() }
        runCatching { codec?.release() }
        runCatching { surface?.release() }
        parameterSets = null
    }

    /** The smallest 4:3 size from 320×240 up — the lane carries no more. */
    private fun pickSize(characteristics: CameraCharacteristics): Size {
        val map = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
        val sizes = map?.getOutputSizes(MediaCodec::class.java)?.toList().orEmpty()
        return sizes.filter { it.width * 3 == it.height * 4 && it.width >= 320 }.minByOrNull { it.width }
            ?: sizes.minByOrNull { it.width * it.height }
            ?: Size(640, 480)
    }

    private fun fpsRange(characteristics: CameraCharacteristics): Range<Int>? {
        val ranges = characteristics.get(CameraCharacteristics.CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES) ?: return null
        return ranges.firstOrNull { it.lower == FPS && it.upper == FPS }
            ?: ranges.filter { it.upper >= FPS }.minByOrNull { it.upper }
    }

    // --- H.264, out ----------------------------------------------------------------

    private fun makeEncoder(size: Size): MediaCodec {
        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, size.width, size.height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            // About two thirds of the lane on average: a keyframe still drains
            // in well under a second.
            setInteger(MediaFormat.KEY_BIT_RATE, 150_000)
            setInteger(MediaFormat.KEY_FRAME_RATE, FPS)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 4)
            setInteger(MediaFormat.KEY_PROFILE, MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline)
            setInteger(MediaFormat.KEY_LEVEL, MediaCodecInfo.CodecProfileLevel.AVCLevel31)
            setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_CBR)
        }
        val codec = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
        try {
            codec.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        } catch (e: Exception) {
            // Some encoders refuse CBR; the core pads either way.
            format.setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
            codec.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        }
        return codec
    }

    private fun encodeLoop(codec: MediaCodec) {
        val info = MediaCodec.BufferInfo()
        var lastKeyframeRequest = 0L
        while (running.get() && !Thread.currentThread().isInterrupted) {
            if (media.videoNeedsKeyframe && System.nanoTime() - lastKeyframeRequest > KEYFRAME_SPACING_NS) {
                lastKeyframeRequest = System.nanoTime()
                runCatching { codec.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) }) }
            }
            val index = try {
                codec.dequeueOutputBuffer(info, CODEC_TIMEOUT_US)
            } catch (e: IllegalStateException) {
                return
            }
            if (index < 0) continue
            val buffer = codec.getOutputBuffer(index)
            if (buffer != null && info.size > 0) {
                val bytes = ByteArray(info.size)
                buffer.position(info.offset)
                buffer.get(bytes)
                if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                    // SPS and PPS: kept, and put in front of every keyframe so a
                    // decoder can start from any of them.
                    parameterSets = bytes
                } else {
                    val keyframe = info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0
                    val data = if (keyframe) (parameterSets ?: ByteArray(0)) + bytes else bytes
                    stats.encoded++
                    val elapsed = ((System.nanoTime() - started) / 1_000_000).toInt()
                    if (media.pushVideo(VideoUnit(data, keyframe, sensorTurns, elapsed))) {
                        stats.sent++
                    } else {
                        stats.dropped++
                        runCatching { codec.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) }) }
                    }
                }
            }
            runCatching { codec.releaseOutputBuffer(index, false) }
        }
    }

    // --- H.264, in -----------------------------------------------------------------

    /**
     * Take every unit that arrived with the last receive. Runs on [CallAudio]'s
     * receiving thread, so it never blocks: a full queue drops the oldest.
     */
    fun drainRemote() {
        while (true) {
            val unit = media.takeVideo() ?: break
            stats.received++
            while (!incoming.offer(unit)) incoming.poll()
        }
        val off = media.peerCameraOff
        if (off != remote.cameraOff) updateRemote(remote.copy(cameraOff = off))
    }

    private fun decodeLoop() {
        val info = MediaCodec.BufferInfo()
        while (running.get()) {
            val unit = try {
                incoming.poll(100, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                return
            } ?: continue
            synchronized(lock) {
                val codec = decoderFor(unit) ?: return@synchronized
                feed(codec, unit)
                drain(codec, info)
            }
            if (unit.rotation != remoteTurns) {
                remoteTurns = unit.rotation
                main.post { onRemoteRotation?.invoke(remoteTurns) }
            }
        }
    }

    /** The decoder for this unit's stream, made — or remade — from its parameter sets. */
    private fun decoderFor(unit: VideoUnit): MediaCodec? {
        val surface = remoteSurface ?: return null
        val nals = nalUnits(unit.data)
        val sps = nals.firstOrNull { it.isNotEmpty() && (it[0].toInt() and 0x1f) == 7 }
        val pps = nals.firstOrNull { it.isNotEmpty() && (it[0].toInt() and 0x1f) == 8 }
        val current = decoder
        if (sps != null && pps != null &&
            (current == null || !sps.contentEquals(decoderSps) || !pps.contentEquals(decoderPps))
        ) {
            runCatching { current?.stop() }
            runCatching { current?.release() }
            decoder = null
            val (width, height) = 640 to 480
            val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height).apply {
                setByteBuffer("csd-0", ByteBuffer.wrap(START_CODE + sps))
                setByteBuffer("csd-1", ByteBuffer.wrap(START_CODE + pps))
            }
            decoder = runCatching {
                MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC).apply {
                    configure(format, surface, null, 0)
                    start()
                }
            }.getOrNull()
            decoderSps = sps
            decoderPps = pps
        }
        return decoder
    }

    private fun feed(codec: MediaCodec, unit: VideoUnit) {
        val index = runCatching { codec.dequeueInputBuffer(CODEC_TIMEOUT_US) }.getOrDefault(-1)
        if (index < 0) return
        val buffer = codec.getInputBuffer(index) ?: return
        buffer.clear()
        if (unit.data.size > buffer.remaining()) return
        buffer.put(unit.data)
        val flags = if (unit.keyframe) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0
        runCatching { codec.queueInputBuffer(index, 0, unit.data.size, unit.timestampMs * 1_000L, flags) }
    }

    private fun drain(codec: MediaCodec, info: MediaCodec.BufferInfo) {
        while (true) {
            val index = runCatching { codec.dequeueOutputBuffer(info, 0) }.getOrDefault(-1)
            if (index < 0) return
            runCatching { codec.releaseOutputBuffer(index, true) }
            stats.shown++
            if (!remote.started) updateRemote(remote.copy(started = true))
        }
    }

    private fun updateRemote(state: RemoteVideoState) {
        remote = state
        main.post { onRemoteState?.invoke(state) }
    }

    companion object {
        private const val FPS = 15
        private const val CODEC_TIMEOUT_US = 10_000L
        private const val MAX_WAITING_UNITS = 30
        private val KEYFRAME_SPACING_NS = TimeUnit.MILLISECONDS.toNanos(800)
        private val START_CODE = byteArrayOf(0, 0, 0, 1)

        /** Split an Annex B stream at its start codes. */
        fun nalUnits(data: ByteArray): List<ByteArray> {
            val units = mutableListOf<ByteArray>()
            var start = -1
            var i = 0
            while (i + 3 <= data.size) {
                val three = data[i].toInt() == 0 && data[i + 1].toInt() == 0 && data[i + 2].toInt() == 1
                val four = i + 4 <= data.size && data[i].toInt() == 0 && data[i + 1].toInt() == 0 &&
                    data[i + 2].toInt() == 0 && data[i + 3].toInt() == 1
                if (three || four) {
                    if (start in 0 until i) units.add(data.copyOfRange(start, i))
                    i += if (four) 4 else 3
                    start = i
                } else {
                    i++
                }
            }
            if (start in 0 until data.size) units.add(data.copyOfRange(start, data.size))
            return units
        }

        /** Turn a texture view's content upright: [turns] quarter turns clockwise, filling the view. */
        fun uprightMatrix(view: TextureView, turns: Int): Matrix {
            val width = view.width.toFloat()
            val height = view.height.toFloat()
            val matrix = Matrix()
            if (width == 0f || height == 0f) return matrix
            val cx = width / 2
            val cy = height / 2
            matrix.postRotate(90f * turns, cx, cy)
            if (turns % 2 == 1) {
                // Sideways content: swap the axes so it still fills the view.
                matrix.postScale(height / width, width / height, cx, cy)
            }
            return matrix
        }
    }
}
