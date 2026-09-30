package app.void

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

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
                        state.torStatus == TorStatus.FAILED -> "Offline — retrying"
                        else -> "Offline"
                    }
                    if (label != null) {
                        Text(label, modifier = Modifier.padding(end = 8.dp), color = MaterialTheme.colorScheme.error)
                    }
                    TextButton(onClick = { state.screen = Screen.Security }) { Text("Security") }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onNewContact) { Text("+") }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.isOffline) {
                // NFR-REL-04 and FR-TRANS-05: nothing is being sent, and that
                // is deliberate. A bare "no connection" invites a workaround;
                // there isn't one, by design.
                Text(
                    "Messages are saved on this phone and will send when Void can reach the network. " +
                        "Nothing is sent any other way.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
            if (state.conversations.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.padding(32.dp),
                    ) {
                        Text("No conversations", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Void has no directory and no way to look people up. You start a conversation " +
                                "by scanning someone's code in person, or by sending them a one-time link " +
                                "through another app.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Button(onClick = onNewContact) { Text("Add a contact") }
                    }
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(vertical = 4.dp)) {
                    items(state.conversations, key = { it.key }) { contact ->
                        Card(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                            onClick = { onOpenConversation(contact) },
                        ) {
                            Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(contact.name.ifBlank { "Unnamed contact" }, style = MaterialTheme.typography.titleMedium)
                                    Text(contact.trust.statusLine, style = MaterialTheme.typography.bodySmall)
                                    val last = state.lastMessage(contact.key)
                                    if (last.isNotEmpty()) {
                                        Text(
                                            last,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            maxLines = 1,
                                        )
                                    }
                                }
                                val count = state.unread[contact.key] ?: 0
                                if (count > 0) Badge { Text("$count") }
                            }
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
    var renaming by remember { mutableStateOf(false) }
    val messages = state.messagesByFingerprint[contact.key].orEmpty()
    val listState = rememberLazyListState()
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(contact.name.ifBlank { "Unnamed contact" }) },
                navigationIcon = { TextButton(onClick = onBack) { Text("Back") } },
                actions = {
                    TextButton(
                        onClick = { state.requestCall(contact.fingerprint) },
                        enabled = contact.trust.canSend,
                        modifier = Modifier.testTag("callButton"),
                    ) { Text("Call") }
                    TextButton(onClick = onVerify) { Text("Verify") }
                    TextButton(onClick = { renaming = true }) { Text("Rename") }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (contact.trust != TrustState.VERIFIED) {
                TrustBanner(
                    trust = contact.trust,
                    onCheck = onVerify,
                    // Goes to the engine, which is what actually blocks sending;
                    // drops to "not verified", never straight to "verified".
                    onContinue = { state.acknowledgeKeyChange(contact.fingerprint) },
                )
            }
            LazyColumn(
                state = listState,
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentPadding = PaddingValues(12.dp),
            ) {
                items(messages) { message ->
                    Box(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        contentAlignment = if (message.isMine) Alignment.CenterEnd else Alignment.CenterStart,
                    ) {
                        Column(horizontalAlignment = if (message.isMine) Alignment.End else Alignment.Start) {
                            Card { Text(message.text, modifier = Modifier.padding(10.dp)) }
                            if (message.isMine && message.delivery.label.isNotEmpty()) {
                                Text(
                                    message.delivery.label,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (message.delivery == DeliveryState.FAILED) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                            }
                        }
                    }
                }
            }
            ComposerArea(
                trust = contact.trust,
                draft = draft,
                onDraftChanged = { draft = it },
                onSend = {
                    val text = draft.trim()
                    if (text.isNotEmpty()) {
                        // Queued, not sent: the engine holds it until the next
                        // scheduled slot so that send timing does not reveal
                        // typing timing (FR-MSG-06).
                        state.send(contact.fingerprint, text)
                        draft = ""
                    }
                },
            )
        }
    }

    if (renaming) {
        RenameDialog(
            current = contact.name,
            onSave = { name ->
                state.renameContact(contact.fingerprint, name)
                renaming = false
            },
            onCancel = { renaming = false },
        )
    }
}

/** FR-UI-03: trust state as sentences, and a changed key's two ways forward. */
@Composable
private fun TrustBanner(trust: TrustState, onCheck: () -> Unit, onContinue: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(trust.statusLine, style = MaterialTheme.typography.titleSmall)
            Text(trust.guidance, style = MaterialTheme.typography.bodySmall)
            if (trust == TrustState.KEY_CHANGED) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onCheck) { Text("Check their code") }
                    OutlinedButton(onClick = onContinue) { Text("I've checked, continue") }
                }
            }
        }
    }
}

/** The name is only ever this device's: renaming tells nobody. */
@Composable
private fun RenameDialog(current: String, onSave: (String) -> Unit, onCancel: () -> Unit) {
    var name by remember { mutableStateOf(current) }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Rename") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Only you see this name.", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(value = name, onValueChange = { name = it }, singleLine = true)
            }
        },
        confirmButton = { TextButton(onClick = { onSave(name) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerificationScreen(state: AppState, contact: Engine.ContactSummary, onBack: () -> Unit) {
    val theirWords = remember(contact.key) { VoidCore.fingerprintRenderWords(contact.fingerprint) }

    Scaffold(topBar = { TopAppBar(title = { Text("Verify security code") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "Compare these codes with ${contact.name.ifBlank { "your contact" }} in person, or on a " +
                    "call where you recognise their voice. Do not compare them inside Void — if someone " +
                    "is intercepting this conversation, they would be showing you their own codes.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text("Their code:", style = MaterialTheme.typography.labelMedium)
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

/** NFR-COMP-02: where this device's key actually is, from [KeyVault]. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityScreen(state: AppState, onBack: () -> Unit) {
    Scaffold(topBar = { TopAppBar(title = { Text("Security") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            KeyStorageScreen(backing = state.backing)
        }
    }
}

/**
 * Adding a contact (FR-DISC-01), both ways round: show my code to someone, or
 * scan or paste theirs. Each invitation is for one person and is one QR code
 * (D-027). Mirrors `ios/Void/VoidApp.swift`'s `NewContactView`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewContactScreen(state: AppState, onDone: () -> Unit) {
    var tab by remember { mutableIntStateOf(if (state.openedInvite != null) 1 else 0) }
    var showingScanner by remember { mutableStateOf(false) }

    if (showingScanner) {
        InviteScanScreen(
            onScanned = { link ->
                showingScanner = false
                state.openInvite(link)
            },
            onCancel = { showingScanner = false },
        )
        return
    }

    LaunchedEffect(state.openedInvite != null) {
        if (state.openedInvite != null) tab = 1
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add a contact") },
                navigationIcon = { TextButton(onClick = onDone) { Text("Close") } },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Show my code") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Scan or paste") })
            }
            Column(
                modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (tab == 0) ShowMyCode(state, onDone) else ScanOrPaste(state, onScan = { showingScanner = true })
            }
        }
    }
}

@Composable
private fun ShowMyCode(state: AppState, onDone: () -> Unit) {
    val invite = state.shownInvite
    val clipboard = LocalClipboardManager.current
    var contactLabel by remember { mutableStateOf("") }

    if (invite == null) {
        Text("Who's this for?", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = contactLabel,
            onValueChange = { contactLabel = it },
            label = { Text("Their name (optional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "Only you see this. They'll appear under this name when they connect.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text("Your name on invitations", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = state.inviteName,
            onValueChange = { state.inviteName = it },
            label = { Text("Your name (optional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "Shown to whoever opens your invitation, so they know it's from you. Anyone can type any " +
                "name, which is why you compare security codes.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = { state.createInvite(contactLabel) },
            modifier = Modifier.fillMaxWidth().testTag("createInviteButton"),
        ) { Text("Create a code") }
        return
    }

    InviteQrCode(link = invite.link, modifier = Modifier.fillMaxWidth().height(260.dp).testTag("inviteQRCode"))
    Text(inviteStatus(state, invite), style = MaterialTheme.typography.bodyMedium)
    Text(invite.link, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
    OutlinedButton(onClick = { clipboard.setText(AnnotatedString(invite.link)) }) { Text("Copy link") }
    Text(
        "One code is for one person, and it works for 24 hours. Anyone who has it can use it, so send " +
            "the link only to them.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (invite.joinedName != null) {
        Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("Done") }
    } else {
        OutlinedButton(onClick = { state.dismissShownInvite() }, modifier = Modifier.fillMaxWidth()) {
            Text("Make a code for someone else")
        }
        TextButton(onClick = { state.cancelShownInvite() }, modifier = Modifier.fillMaxWidth()) {
            Text("Cancel this invitation", color = MaterialTheme.colorScheme.error)
        }
    }
}

private fun inviteStatus(state: AppState, invite: ShownInvite): String {
    val who = invite.contactLabel.ifBlank { "them" }
    invite.joinedName?.let { return "$it joined. You can message them now." }
    if (invite.expired) return "This code expired. Make a new one."
    val remaining = invite.uploadRemaining ?: return "Getting it ready…"
    if (remaining == 0) return "Ready. Show this code to $who, or send them the link."
    if (state.isOffline) return "Waiting for the network. The code will work once Void is online."
    // One record leaves per five-second slot.
    return "Getting it ready — about ${maxOf(5, remaining * 5)} seconds. They can scan it now and wait."
}

@Composable
private fun ScanOrPaste(state: AppState, onScan: () -> Unit) {
    val opened = state.openedInvite
    var pasted by remember { mutableStateOf("") }
    var confirmName by remember { mutableStateOf("") }
    var confirmMessage by remember { mutableStateOf("") }

    if (opened == null) {
        Button(onClick = onScan, modifier = Modifier.fillMaxWidth()) { Text("Scan their code") }
        Text("Or paste their link", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = pasted,
            onValueChange = { pasted = it },
            label = { Text("void://…") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                state.openInvite(pasted)
                pasted = ""
            },
            enabled = pasted.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Open") }
        return
    }

    when (val stage = opened.stage) {
        OpenedInvite.Stage.Fetching -> {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator()
                Text("Getting their invitation…")
            }
            Text(
                "This usually takes a few seconds, and up to a minute if they have only just made it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = { state.cancelOpenedInvite() }) { Text("Cancel") }
        }
        is OpenedInvite.Stage.Ready -> {
            LaunchedEffect(opened.fetchId) {
                if (confirmName.isEmpty()) confirmName = stage.inviterName
            }
            Text(
                if (stage.inviterName.isBlank()) "Connect with this person?" else "Connect with ${stage.inviterName}?",
                style = MaterialTheme.typography.titleMedium,
            )
            OutlinedTextField(
                value = confirmName,
                onValueChange = { confirmName = it },
                label = { Text("Their name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = confirmMessage,
                onValueChange = { confirmMessage = it },
                label = { Text("First message (optional)") },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "Their security code is ${VoidCore.fingerprintRenderWords(stage.fingerprint)}. Compare it with " +
                    "them in person to be sure it's really them.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { state.confirmOpenedInvite(confirmName, confirmMessage) },
                modifier = Modifier.fillMaxWidth().testTag("confirmInviteButton"),
            ) { Text("Connect") }
            TextButton(onClick = { state.cancelOpenedInvite() }) { Text("Cancel") }
        }
        is OpenedInvite.Stage.Failed -> {
            Text(stage.message, style = MaterialTheme.typography.bodyMedium)
            Button(onClick = { state.cancelOpenedInvite() }) { Text("Try another invitation") }
        }
    }
}
