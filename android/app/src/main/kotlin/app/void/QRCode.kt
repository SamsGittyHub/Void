package app.void

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder

/**
 * QR rendering for invite links (FR-DISC-01) — mirrors `ios/Void/QRCode.swift`
 * exactly, including the reason one link needs several codes.
 *
 * ## Why one link needs several QR codes
 *
 * A Void invite link carries a full prekey bundle: an ML-DSA-87 identity key
 * (2,592 bytes) and its hybrid signature (~4,691 bytes) alongside the
 * classical X25519/Ed25519 material and the ML-KEM-1024 prekey (1,568
 * bytes) — there is no directory to look any of that up from later, so it
 * all has to travel in the invite itself. Base32-encoded, a real link is
 * around 14,600 characters, well past the ~4,296 characters the largest QR
 * code (version 40, error correction L) can hold. [QRChunker] splits the
 * link the same way `QRChunker` does on iOS — `VOID1/i/n/data` frames a
 * reader reassembles in order — and [InviteQRCodeCarousel] shows them as
 * swipeable pages. `QRScanner.kt` is what reads the sequence back in.
 */
object QRChunker {
    /** Same rationale and same value as iOS's `QRChunker.chunkSize`. */
    const val CHUNK_SIZE = 1200

    fun chunks(payload: String): List<String> {
        if (payload.isEmpty()) return emptyList()
        val total = ((payload.length + CHUNK_SIZE - 1) / CHUNK_SIZE)
        return (0 until total).map { i ->
            val start = i * CHUNK_SIZE
            val end = minOf(start + CHUNK_SIZE, payload.length)
            "VOID1/${i + 1}/$total/${payload.substring(start, end)}"
        }
    }
}

private fun renderQrBitmap(content: String): Bitmap? =
    try {
        BarcodeEncoder().encodeBitmap(content, BarcodeFormat.QR_CODE, 512, 512)
    } catch (_: Exception) {
        null
    }

@Composable
private fun QrCodeImage(content: String, modifier: Modifier = Modifier) {
    val bitmap = remember(content) { renderQrBitmap(content) }
    if (bitmap != null) {
        Image(
            bitmap = bitmap.asImageBitmap(),
            contentDescription = "QR code",
            modifier = modifier,
        )
    } else {
        Text("Could not render this code", style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * Swipeable pages through every QR code a link needs. Shows one page
 * directly, without paging chrome, when the whole link fits in one code.
 */
@Composable
fun InviteQrCodeCarousel(link: String, modifier: Modifier = Modifier) {
    val frames = remember(link) { QRChunker.chunks(link) }
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        if (frames.size > 1) {
            val pagerState = rememberPagerState(pageCount = { frames.size })
            HorizontalPager(state = pagerState, modifier = Modifier.fillMaxWidth().height(280.dp)) { page ->
                QrCodeImage(
                    content = frames[page],
                    modifier = Modifier.fillMaxWidth().padding(8.dp),
                )
            }
            Text(
                "Page ${pagerState.currentPage + 1} of ${frames.size}",
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.fillMaxWidth(),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
            )
            Text(
                "This invite needs ${frames.size} codes because of the post-quantum keys " +
                    "involved — swipe through all of them, or share the link below instead.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (frames.isNotEmpty()) {
            QrCodeImage(
                content = frames[0],
                modifier = Modifier.fillMaxWidth().height(240.dp),
            )
            Text(
                "Share this code, or the link below, with one person.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
