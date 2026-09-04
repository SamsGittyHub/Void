package app.void

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationListScreen(
    state: AppState,
    onOpenConversation: (Engine.ContactSummary) -> Unit,
    onNewContact: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Void") },
                actions = {
                    val label = when {
                        !state.isOffline -> null
                        state.torStatus == TorStatus.BOOTSTRAPPING -> "Connecting via Tor…"
                        state.torStatus == TorStatus.FAILED -> "Tor unavailable"
                        else -> "Offline"
                    }
                    if (label != null) {
                        Text(label, modifier = Modifier.padding(end = 16.dp), color = MaterialTheme.colorScheme.error)
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onNewContact) { Text("+") }
        },
    ) { padding ->
        if (state.conversations.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("No conversations", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Add a contact to start one — from a QR code or a pasted link.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(onClick = onNewContact) { Text("Add a contact") }
                }
            }
        } else {
            LazyColumn(contentPadding = padding.let { PaddingValues(top = it.calculateTopPadding()) }) {
                items(state.conversations) { contact ->
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                        onClick = { onOpenConversation(contact) },
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(contact.name.ifBlank { "Unnamed contact" }, style = MaterialTheme.typography.titleMedium)
                            Text(contact.trust.statusLine, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationScreen(state: AppState, contact: Engine.ContactSummary, onBack: () -> Unit, onVerify: () -> Unit) {
    var draft by remember { mutableStateOf("") }
    val key = hex(contact.fingerprint)
    val messages = state.messagesByFingerprint[key].orEmpty()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(contact.name.ifBlank { "Unnamed contact" }) },
                navigationIcon = { TextButton(onClick = onBack) { Text("Back") } },
                actions = { TextButton(onClick = onVerify) { Text("Verify") } },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth(), contentPadding = PaddingValues(12.dp)) {
                items(messages) { message ->
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        contentAlignment = if (message.isMine) Alignment.CenterEnd else Alignment.CenterStart,
                    ) {
                        Card {
                            Text(message.text, modifier = Modifier.padding(10.dp))
                        }
                    }
                }
            }
            ComposerArea(
                trust = contact.trust,
                draft = draft,
                onDraftChanged = { draft = it },
                onSend = {
                    if (draft.isNotBlank()) {
                        state.send(contact.fingerprint, draft)
                        draft = ""
                    }
                },
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerificationScreen(state: AppState, contact: Engine.ContactSummary, onBack: () -> Unit) {
    val theirWords = remember(contact.fingerprint) { VoidCore.fingerprintRenderWords(contact.fingerprint) }

    Scaffold(topBar = { TopAppBar(title = { Text("Verify security code") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Read these words to ${contact.name.ifBlank { "your contact" }} over a call you trust, or compare in person.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Card {
                Text(
                    theirWords,
                    modifier = Modifier.padding(16.dp).fillMaxWidth(),
                    style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }
            Text("Your code:", style = MaterialTheme.typography.labelMedium)
            Card {
                Text(
                    state.fingerprintWords,
                    modifier = Modifier.padding(16.dp).fillMaxWidth(),
                    style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Button(
                    onClick = { state.handleVerificationResult(contact.fingerprint, matched = true); onBack() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("These match") }
                OutlinedButton(
                    onClick = { state.handleVerificationResult(contact.fingerprint, matched = false); onBack() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("These don't match") }
            }
        }
    }
}

/**
 * The "add a contact" screen (FR-DISC-01): shows my invite as a QR carousel
 * or accepts a pasted/scanned link. Mirrors `ios/Void/VoidApp.swift`'s
 * `NewContactView` plus `QRCode.swift`/`QRScanner.swift`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewContactScreen(state: AppState, onDone: () -> Unit) {
    var myInviteLink by remember { mutableStateOf<String?>(null) }
    var pastedLink by remember { mutableStateOf("") }
    var contactName by remember { mutableStateOf("") }
    var firstMessage by remember { mutableStateOf("") }
    var showingScanner by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current

    if (showingScanner) {
        InviteScanScreen(
            onScanned = { link -> pastedLink = link; showingScanner = false },
            onCancel = { showingScanner = false },
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add a contact") },
                navigationIcon = { TextButton(onClick = onDone) { Text("Close") } },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Text("Your invite", style = MaterialTheme.typography.titleMedium)
            val link = myInviteLink
            if (link != null) {
                InviteQrCodeCarousel(link = link, modifier = Modifier.fillMaxWidth())
                Text(link, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(link)) }) { Text("Copy link") }
            } else {
                Button(onClick = { myInviteLink = state.createInvite() }) { Text("Generate an invite") }
            }

            Text("Accept an invite", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { showingScanner = true }) { Text("Scan a QR code") }
            OutlinedTextField(
                value = pastedLink,
                onValueChange = { pastedLink = it },
                label = { Text("Paste a void:// link") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = contactName,
                onValueChange = { contactName = it },
                label = { Text("Their name (just for you)") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = firstMessage,
                onValueChange = { firstMessage = it },
                label = { Text("First message") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    state.startConversation(pastedLink, contactName, firstMessage)
                    onDone()
                },
                enabled = pastedLink.isNotBlank() && firstMessage.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Start conversation") }
        }
    }
}
