package app.void

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Picking, confirming, showing and saving files in a conversation — the
 * Kotlin mirror of `ios/Void/Attachments.swift`.
 *
 * ## A file is a message
 *
 * Nothing about sending a file is different on the wire from sending text
 * (`void_proto::content`, D-032): the same ratchet, the same fixed-size
 * records, one per emission slot. The relay cannot tell a photo from the same
 * number of texts. What a file costs is time — a photo is hundreds of records
 * at one every five seconds — and this file's job is to say so, in numbers,
 * before the user commits to it (non-negotiable #8: every option states its
 * cost).
 *
 * ## Photos are shrunk, on purpose
 *
 * A camera photo is several megabytes; the protocol carries 500 KiB in one
 * message. Pictures are re-encoded at a size that reads well on a phone and
 * sends in minutes. Re-encoding also drops the camera's metadata — location,
 * device, time — which a messenger built around not leaking who and where
 * should not forward by accident.
 *
 * ## Nothing here reaches the core
 *
 * Pickers, image codecs, the document picker for saving. Bytes go to
 * [AppState.sendFile] and come back from [AppState.attachment]; that is the
 * whole interface.
 */
object AttachmentFormat {
    /** "240 KB", "1.2 MB". */
    fun size(bytes: Int): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${(bytes + 512) / 1024} KB"
        else -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    }

    /** "40 seconds", "4 minutes". Rounded up: a promise of time is better kept short than broken. */
    fun duration(seconds: Int): String {
        if (seconds < 60) return "${maxOf(seconds, 5)} seconds"
        val minutes = (seconds + 59) / 60
        return if (minutes == 1) "1 minute" else "$minutes minutes"
    }

    /** How long a file of this size takes to send, in seconds, at most. */
    fun sendSeconds(bytes: Int): Int = VoidCore.fileRecordCount(bytes) * (VoidCore.padIntervalMs() / 1000).toInt()
}

/** Turns what the pickers hand back into bytes the protocol can carry. */
object AttachmentImport {
    /** Longest side of a sent picture, in pixels: reads well on a phone, lands around 100–250 KB as JPEG. */
    private const val MAX_IMAGE_SIDE = 1280

    /** A file the picker named but that could not be read. */
    class Unreadable : Exception("That file couldn't be read.")

    class TooLarge(val size: Int) : Exception() {
        override val message: String
            get() = "This file is ${AttachmentFormat.size(size)}. Void sends files of up to " +
                "${AttachmentFormat.size(VoidCore.fileMaxBytes())} in one message; photos are shrunk to fit, " +
                "other files are not."
    }

    /** Read a picked document or picture. Pictures are shrunk; anything else is sent as it is, or refused. */
    fun fromUri(context: Context, uri: Uri): PendingAttachment {
        val resolver = context.contentResolver
        val mime = resolver.getType(uri).orEmpty()
        var name = ""
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) name = cursor.getString(0).orEmpty()
        }
        val data = resolver.openInputStream(uri)?.use { it.readBytes() } ?: throw Unreadable()
        if (mime.startsWith("image/")) {
            shrink(data, name.ifBlank { "photo-${stamp()}.jpg" })?.let { return it }
        }
        if (data.size > VoidCore.fileMaxBytes()) throw TooLarge(data.size)
        return PendingAttachment(name, mime, data)
    }

    /**
     * Re-encode a picture as JPEG under the bound: by size first, then quality,
     * then smaller again. Always a fresh encoding, which drops the camera's
     * metadata with it. Null if the bytes are not a picture.
     */
    fun shrink(imageData: ByteArray, name: String): PendingAttachment? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(imageData, 0, imageData.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var longest = maxOf(bounds.outWidth, bounds.outHeight)
        // Decode at a power-of-two reduction close to the target, then scale.
        var sample = 1
        while (longest / (sample * 2) >= MAX_IMAGE_SIDE) sample *= 2
        val decoded = BitmapFactory.decodeByteArray(imageData, 0, imageData.size, BitmapFactory.Options().apply { inSampleSize = sample })
            ?: return null
        var bitmap = decoded
        var side = minOf(MAX_IMAGE_SIDE, maxOf(bitmap.width, bitmap.height))
        var quality = 70
        val limit = VoidCore.fileMaxBytes()
        repeat(8) {
            longest = maxOf(bitmap.width, bitmap.height)
            if (longest > side) {
                val scale = side.toFloat() / longest
                val scaled = Bitmap.createScaledBitmap(bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1), (bitmap.height * scale).toInt().coerceAtLeast(1), true)
                if (scaled !== bitmap && bitmap !== decoded) bitmap.recycle()
                bitmap = scaled
            }
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, quality, out)
            val jpeg = out.toByteArray()
            if (jpeg.size <= limit) {
                val base = name.substringBeforeLast('.', name)
                return PendingAttachment("$base.jpg", "image/jpeg", jpeg)
            }
            if (quality > 40) quality -= 15 else { side = (side * 0.7).toInt(); quality = 70 }
        }
        return null
    }

    private fun stamp(): String = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
}

/**
 * The two ways to attach — a photo, or any file — as a pair of buttons for the
 * composer. [onPicked] gets the file once read and, for a picture, shrunk;
 * confirmation is the caller's.
 */
@Composable
fun AttachmentButtons(onPicked: (PendingAttachment) -> Unit, onFailed: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    fun handle(uri: Uri?) {
        if (uri == null) return
        scope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { AttachmentImport.fromUri(context, uri) } }
            result.onSuccess(onPicked).onFailure { e ->
                onFailed(
                    when (e) {
                        is AttachmentImport.TooLarge, is AttachmentImport.Unreadable -> e.message.orEmpty()
                        else -> "That file couldn't be read."
                    },
                )
            }
        }
    }
    val photos = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { handle(it) }
    val documents = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { handle(it) }
    TextButton(
        onClick = { photos.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
        modifier = Modifier.testTag("attachPhotoButton"),
    ) { Text("Photo") }
    TextButton(
        onClick = { documents.launch(arrayOf("*/*")) },
        modifier = Modifier.testTag("attachFileButton"),
    ) { Text("File") }
}

/**
 * Before a file is queued: what it is, how big, and how long it will take —
 * because a photo takes minutes, not the instant a text takes, and someone who
 * is not told that concludes the app is broken.
 */
@Composable
fun AttachmentConfirmDialog(pending: PendingAttachment, contactName: String, onSend: () -> Unit, onCancel: () -> Unit) {
    val seconds = AttachmentFormat.sendSeconds(pending.data.size)
    val preview = remember(pending) {
        if (pending.mime.startsWith("image/")) BitmapFactory.decodeByteArray(pending.data, 0, pending.data.size) else null
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Send this file?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (preview != null) {
                    Image(
                        bitmap = preview.asImageBitmap(),
                        contentDescription = "The photo to send",
                        modifier = Modifier.fillMaxWidth().heightIn(max = 200.dp),
                        contentScale = ContentScale.Fit,
                    )
                } else {
                    Text(pending.name.ifBlank { "File" }, style = MaterialTheme.typography.titleSmall)
                }
                Text(
                    "${AttachmentFormat.size(pending.data.size)} — about ${AttachmentFormat.duration(seconds)} to send.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag("attachmentEstimate"),
                )
                // Non-negotiable #8: the cost, and why. Not an apology; the
                // slowness is the privacy.
                Text(
                    "Void sends everything at one fixed pace, in pieces that all look the same, so nobody " +
                        "watching can tell a photo from a few messages. That is why a file takes longer. You " +
                        "can keep using Void while it sends, and anything you write to $contactName meanwhile " +
                        "goes out first.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { Button(onClick = onSend, modifier = Modifier.testTag("sendAttachmentButton")) { Text("Send") } },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

/**
 * A file in the conversation: the picture itself, or a card with its name and
 * size, and a way to save it. The bytes are fetched when the bubble appears
 * and kept by [AppState] while the conversation is open.
 */
@Composable
fun AttachmentBubble(state: AppState, message: MessageItem, attachment: AttachmentInfo) {
    var data by remember(message.recordId) { mutableStateOf<ByteArray?>(null) }
    LaunchedEffect(message.recordId) {
        if (message.recordId != 0L && data == null) data = state.attachment(message.recordId)
    }
    val bitmap = remember(data) {
        val bytes = data
        if (attachment.isImage && bytes != null) BitmapFactory.decodeByteArray(bytes, 0, bytes.size) else null
    }
    // The system's own "save as" picker: the user chooses where, and the bytes
    // go straight from memory to the place they chose. Nothing is written to
    // app storage under the file's name — a photo on disk under its own name
    // is the plaintext column the database promises not to keep.
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(attachment.mime.ifBlank { "application/octet-stream" })) { uri ->
        val bytes = data
        if (uri != null && bytes != null) {
            runCatching { stateContextWrite(state, uri, bytes) }
        }
    }
    Card(modifier = Modifier.widthIn(max = 280.dp)) {
        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            when {
                bitmap != null -> Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "Photo",
                    modifier = Modifier.fillMaxWidth().heightIn(max = 260.dp),
                    contentScale = ContentScale.Fit,
                )
                data == null && message.recordId != 0L -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CircularProgressIndicator(modifier = Modifier.padding(2.dp))
                    Text(attachment.summary, style = MaterialTheme.typography.bodySmall)
                }
                else -> Column {
                    Text(attachment.name.ifBlank { attachment.summary }, style = MaterialTheme.typography.titleSmall)
                    Text(AttachmentFormat.size(attachment.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (data != null) {
                TextButton(onClick = { save.launch(attachment.name.ifBlank { if (attachment.isImage) "photo.jpg" else "file" }) }) {
                    Text("Save")
                }
            }
        }
    }
}

/** Write bytes to the document the user chose. */
private fun stateContextWrite(state: AppState, uri: Uri, bytes: ByteArray) {
    state.appContext.contentResolver.openOutputStream(uri, "wt")?.use { it.write(bytes) }
}
