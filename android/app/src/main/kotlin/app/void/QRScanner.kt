package app.void

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
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
 * Reads an invitation's QR code — the other half of FR-DISC-01, and the Kotlin
 * mirror of `ios/Void/QRScanner.swift`. An invitation is one code (D-027), so
 * the first `void://` link in view is the whole thing.
 */
fun isVoidLink(payload: String): Boolean = payload.trim().lowercase().startsWith("void://")

/**
 * The screen presented for "Scan their code": live camera, calling [onScanned]
 * the moment an invitation is in view. Requests the camera permission itself
 * and falls back to a plain message — never a silent dead end — if it is
 * denied. The camera is released when the screen goes away.
 */
@Composable
fun InviteScanScreen(onScanned: (String) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasPermission = granted
    }
    LaunchedEffect(Unit) {
        if (!hasPermission) launcher.launch(Manifest.permission.CAMERA)
    }
    BackHandler(onBack = onCancel)

    Column(modifier = Modifier.fillMaxSize()) {
        TextButton(onClick = onCancel, modifier = Modifier.padding(8.dp)) { Text("Cancel") }
        if (!hasPermission) {
            Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Camera permission is needed to scan a code.", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Paste the invitation link instead, or allow the camera in Settings.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            return@Column
        }

        var done by remember { mutableStateOf(false) }
        var scanner by remember { mutableStateOf<DecoratedBarcodeView?>(null) }
        // Without this the camera stayed on after scanning, until the process died.
        DisposableEffect(Unit) {
            onDispose { scanner?.pause() }
        }

        Box(modifier = Modifier.weight(1f)) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx ->
                    DecoratedBarcodeView(ctx).apply {
                        barcodeView.decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))
                        decodeContinuous(object : BarcodeCallback {
                            override fun barcodeResult(result: BarcodeResult) {
                                val text = result.text ?: return
                                if (done || !isVoidLink(text)) return
                                done = true
                                pause()
                                onScanned(text.trim())
                            }

                            override fun possibleResultPoints(resultPoints: MutableList<ResultPoint>) {}
                        })
                        resume()
                        scanner = this
                    }
                },
            )
            Surface(
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 24.dp),
                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.85f),
                shape = MaterialTheme.shapes.large,
            ) {
                Text(
                    "Point the camera at their Void code",
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}
