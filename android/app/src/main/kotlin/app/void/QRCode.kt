package app.void

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder

/**
 * QR rendering for invitation links (FR-DISC-01) — mirrors `ios/Void/QRCode.swift`.
 *
 * An invitation link is short — `void://i/<relay>#<secret>`, about 130
 * characters — because the invitation itself is parked, encrypted, on the
 * relay (D-027). So it is one small QR code. It used to be the whole signed
 * prekey bundle, about 14,600 characters and thirteen codes to swipe through;
 * full `void://c/` links still open, they are just never shown as a code.
 */
private fun renderQrBitmap(content: String): Bitmap? =
    try {
        BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, 512, 512)
    } catch (_: Exception) {
        null
    }

@Composable
fun InviteQrCode(link: String, modifier: Modifier = Modifier) {
    val bitmap = remember(link) { renderQrBitmap(link) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR code for your invitation",
            modifier = modifier,
        )
    } else {
        Text("Could not render this code", style = MaterialTheme.typography.bodySmall)
    }
}
