package app.void

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope

/**
 * The app entry point.
 *
 * FR-STOR-06's app-switcher protection: [WindowManager.LayoutParams.FLAG_SECURE]
 * is the Android platform mechanism for what iOS needs a manual snapshot
 * overlay for (see `VoidApp.swift`'s `privacyCover`) — it blocks the
 * conversation content from ever reaching a task-switcher thumbnail or a
 * screenshot in the first place, at the OS level, for the whole activity.
 */
class MainActivity : ComponentActivity() {
    private var appState: AppState? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        setContent {
            val state = remember {
                AppState(lifecycleScope).also {
                    appState = it
                    it.startTicking()
                    it.connectTor(
                        stateDir = java.io.File(filesDir, "tor-state"),
                        cacheDir = java.io.File(cacheDir, "tor-cache"),
                        onionAddress = DevRelay.ONION_ADDRESS,
                        port = DevRelay.PORT,
                    )
                }
            }

            MaterialTheme {
                Surface {
                    RootScreen(state)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        appState?.close()
    }
}

private sealed class Screen {
    data object List : Screen()
    data class Conversation(val contact: Engine.ContactSummary) : Screen()
    data class Verification(val contact: Engine.ContactSummary) : Screen()
    data object NewContact : Screen()
}

@androidx.compose.runtime.Composable
private fun RootScreen(state: AppState) {
    if (!state.protectionAcknowledged) {
        OnboardingFlow(onFinished = { state.protectionAcknowledged = true })
        return
    }

    var screen by remember { mutableStateOf<Screen>(Screen.List) }

    when (val current = screen) {
        is Screen.List -> ConversationListScreen(
            state = state,
            onOpenConversation = { screen = Screen.Conversation(it) },
            onNewContact = { screen = Screen.NewContact },
        )
        is Screen.Conversation -> ConversationScreen(
            state = state,
            contact = current.contact,
            onBack = { screen = Screen.List },
            onVerify = { screen = Screen.Verification(current.contact) },
        )
        is Screen.Verification -> VerificationScreen(
            state = state,
            contact = current.contact,
            onBack = { screen = Screen.List },
        )
        is Screen.NewContact -> NewContactScreen(state = state, onDone = { screen = Screen.List })
    }
}
