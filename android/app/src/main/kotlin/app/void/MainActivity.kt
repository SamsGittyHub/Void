package app.void

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat

/**
 * The app entry point.
 *
 * FR-STOR-06's app-switcher protection: [WindowManager.LayoutParams.FLAG_SECURE]
 * is the Android platform mechanism for what iOS needs a manual snapshot
 * overlay for (see `VoidApp.swift`'s `privacyCover`) — it blocks the
 * conversation content from ever reaching a task-switcher thumbnail or a
 * screenshot in the first place, at the OS level, for the whole activity.
 *
 * The engine is not this activity's: [VoidApplication] owns it, so a rotation
 * or any other recreation of this activity leaves it running.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val app = application as VoidApplication

        setContent {
            MaterialTheme {
                Surface {
                    when (val phase = app.phase) {
                        LaunchPhase.Opening -> Centered {
                            CircularProgressIndicator()
                            Text("Opening…", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        is LaunchPhase.Failed -> Centered {
                            Text("Void could not start", style = MaterialTheme.typography.titleMedium)
                            Text(
                                phase.message,
                                style = MaterialTheme.typography.bodyMedium,
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        is LaunchPhase.Ready -> RootScreen(phase.state)
                    }
                }
            }
        }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            content()
        }
    }
}

@Composable
private fun RootScreen(state: AppState) {
    if (!state.protectionAcknowledged) {
        OnboardingFlow(onFinished = { state.finishOnboarding() })
        return
    }

    val call = state.activeCall
    val pending = state.pendingDisclosure
    when {
        // The disclosure comes first, over everything, in either direction.
        pending != null -> DisclosureHost(state, pending)
        call != null -> CallHostScreen(state, call)
        else -> Screens(state)
    }

    state.notice?.let { NoticeBanner(it, onDismiss = { state.dismissNotice() }) }

    state.lastError?.let { message ->
        AlertDialog(
            onDismissRequest = { state.lastError = null },
            confirmButton = { TextButton(onClick = { state.lastError = null }) { Text("OK") } },
            title = { Text("Something went wrong") },
            text = { Text(message) },
        )
    }
}

@Composable
private fun Screens(state: AppState) {
    val screen = state.screen
    BackHandler(enabled = screen != Screen.List) {
        when (screen) {
            is Screen.Conversation -> state.closeConversation()
            is Screen.Verification -> state.openConversation(screen.key)
            is Screen.NewContact -> {
                state.dismissShownInvite()
                state.cancelOpenedInvite()
                state.screen = Screen.List
            }
            Screen.Security -> state.screen = Screen.List
            Screen.List -> {}
        }
    }
    when (screen) {
        Screen.List -> ConversationListScreen(
            state = state,
            onOpenConversation = { state.openConversation(it.key) },
            onNewContact = { state.screen = Screen.NewContact },
        )
        is Screen.Conversation -> {
            val contact = state.contact(screen.key)
            if (contact == null) {
                // Revoked, or not loaded yet: back to the list, after this frame.
                LaunchedEffect(screen) { state.closeConversation() }
            } else {
                ConversationScreen(
                    state = state,
                    contact = contact,
                    onBack = { state.closeConversation() },
                    onVerify = { state.screen = Screen.Verification(screen.key) },
                )
            }
        }
        is Screen.Verification -> {
            val contact = state.contact(screen.key)
            if (contact == null) {
                LaunchedEffect(screen) { state.closeConversation() }
            } else {
                VerificationScreen(
                    state = state,
                    contact = contact,
                    onBack = { state.openConversation(screen.key) },
                )
            }
        }
        Screen.Security -> SecurityScreen(state = state, onBack = { state.screen = Screen.List })
        Screen.NewContact -> NewContactScreen(
            state = state,
            onDone = {
                state.dismissShownInvite()
                state.cancelOpenedInvite()
                state.screen = Screen.List
            },
        )
    }
}

/** The incoming-call screen, or the ringing and in-call one. */
@Composable
private fun CallHostScreen(state: AppState, call: CallSession) {
    val key = call.fingerprint.toHex()
    BackHandler { /* A call is ended with its own button, never by accident. */ }
    if (call.phase == CallPhase.INCOMING) {
        IncomingCallScreen(
            contactName = state.name(key),
            isVerified = state.contact(key)?.trust == TrustState.VERIFIED,
            onAnswer = { state.requestAnswer() },
            onDecline = { state.hangUp() },
        )
    } else {
        CallScreen(
            contactName = state.name(key),
            phase = call.phase,
            isMuted = state.isMuted,
            onMuteChange = { state.mute(it) },
            onHangUp = { state.hangUp() },
        )
    }
}

/**
 * The disclosure, and then the microphone permission — asked for at the moment
 * the user chooses to talk, not at launch for a feature they may never use.
 */
@Composable
private fun DisclosureHost(state: AppState, pending: PendingCall) {
    val context = LocalContext.current
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        state.confirmDisclosure(microphoneGranted = granted)
    }
    BackHandler { state.cancelDisclosure() }
    CallDisclosureScreen(
        contactName = state.contact(pending.fingerprint.toHex())?.name?.ifBlank { null } ?: "them",
        isAnswering = pending.isAnswering,
        onContinue = {
            val granted = ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED
            if (granted) state.confirmDisclosure(microphoneGranted = true) else permission.launch(Manifest.permission.RECORD_AUDIO)
        },
        onCancel = { state.cancelDisclosure() },
    )
}

/** A short line at the top of the screen that goes away on its own. */
@Composable
private fun NoticeBanner(text: String, onDismiss: () -> Unit) {
    Box(modifier = Modifier.fillMaxWidth().padding(top = 40.dp, start = 16.dp, end = 16.dp), contentAlignment = Alignment.TopCenter) {
        Surface(
            color = MaterialTheme.colorScheme.inverseSurface,
            contentColor = MaterialTheme.colorScheme.inverseOnSurface,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.clickable(onClick = onDismiss),
        ) {
            Text(text, modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp), style = MaterialTheme.typography.bodyMedium)
        }
    }
}
