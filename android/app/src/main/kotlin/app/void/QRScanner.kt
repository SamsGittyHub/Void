package app.void

import android.Manifest
import android.content.pm.PackageManager
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory

/**
 * Reads back what `QRCode.kt`'s carousel produces — the other half of
 * FR-DISC-01, and the Kotlin mirror of `ios/Void/QRScanner.swift`.
 *
 * `zxing-android-embedded`'s [DecoratedBarcodeView] decodes continuously
 * rather than closing after one hit, which is what a multi-frame `VOID1`
 * sequence needs — a steady hand rarely gets every frame in one pass, so
 * partial progress persists across frames rather than resetting on every
 * miss, exactly like the iOS `ScanProgress` this mirrors.
 */
object QRReassembler {
    data class Frame(val index: Int, val total: Int, val data: String)

    /** `null` means it wasn't one of ours — a stray QR code in view, not a corrupt scan. */
    fun parse(payload: String): Frame? {
        val parts = payload.split("/", limit = 4)
        if (parts.size != 4 || parts[0] != "VOID1") return null
        val index = parts[1].toIntOrNull() ?: return null
        val total = parts[2].toIntOrNull() ?: return null
        if (index < 1 || total < 1 || index > total) return null
        return Frame(index, total, parts[3])
    }

    /** Joins collected frames back into the original link once all of `1..total` are present. */
    fun reassemble(frames: Map<Int, Frame>): String? {
        val total = frames.values.firstOrNull()?.total ?: return null
        if (frames.values.any { it.total != total }) return null
        if ((1..total).any { frames[it] == null }) return null
        return (1..total).joinToString("") { frames[it]!!.data }
    }
}

/**
 * The screen presented for "Scan a QR code": live camera behind a progress
 * readout, calling [onScanned] and stopping the moment the last chunk
 * lands. Requests the camera permission itself on first composition and
 * falls back to a plain message — never a silent dead end — if it's denied.
 */
@Composable
fun InviteScanScreen(onScanned: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }

    LaunchedEffect(Unit) {
        if (!hasPermission) launcher.launch(Manifest.permission.CAMERA)
    }

    Column(modifier = Modifier.fillMaxSize()) {
        if (!hasPermission) {
            Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("Camera permission is needed to scan a code.", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Paste the invite link instead, or grant the permission in Settings.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            return@Column
        }

        val frames = remember { mutableStateMapOf<Int, QRReassembler.Frame>() }
        var completed by remember { mutableStateOf(false) }

        Box(modifier = Modifier.weight(1f)) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    DecoratedBarcodeView(ctx).apply {
                        barcodeView.decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))
                        decodeContinuous(object : BarcodeCallback {
                            override fun barcodeResult(result: BarcodeResult) {
                                if (completed) return
                                val frame = QRReassembler.parse(result.text) ?: return
                                val existingTotal = frames.values.firstOrNull()?.total
                                if (existingTotal != null && existingTotal != frame.total) {
                                    frames.clear()
                                }
                                frames[frame.index] = frame
                                val joined = QRReassembler.reassemble(frames)
                                if (joined != null) {
                                    completed = true
                                    onScanned(joined)
                                }
                            }

                            override fun possibleResultPoints(resultPoints: MutableList<ResultPoint>) {}
                        })
                        resume()
                    }
                },
            )
            Surface(
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 24.dp),
                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.85f),
                shape = MaterialTheme.shapes.large,
            ) {
                val total = frames.values.firstOrNull()?.total
                Text(
                    text = if (total != null) "${frames.size} of $total codes scanned"
                    else "Point the camera at the first code",
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
