package app.void

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * The two screens the PRD requires before a user can do anything — the
 * Kotlin mirror of `ios/Void/OnboardingViews.swift`, requirement for
 * requirement:
 *
 * - FR-UI-05: "an in-app 'What Void does and does not protect' screen"
 * - FR-REC-01: "during onboarding the user is told... that losing the
 *   device means losing all messages and their identity"
 */

private data class ProtectionItem(val title: String, val body: String)

private val PROTECTS = listOf(
    ProtectionItem(
        "Nobody can read your messages",
        "Not us, not the servers that carry them, not anyone watching the network. " +
            "Only the person you are talking to.",
    ),
    ProtectionItem(
        "A future quantum computer still can't",
        "Someone recording your messages today cannot decrypt them later, even with " +
            "technology that does not exist yet.",
    ),
    ProtectionItem(
        "We never learn who you talk to",
        "There is no account, no phone number, no address book on any server. The " +
            "servers that carry your messages cannot tell that two of them belong to " +
            "the same conversation.",
    ),
    ProtectionItem("Your messages are deleted automatically", "After 30 days by default. You can make that shorter."),
)

private val DOES_NOT_PROTECT = listOf(
    ProtectionItem(
        "A phone someone else controls",
        "If someone installs spyware on your phone, or takes it while it is unlocked, " +
            "they can read what you can read. No messaging app can prevent that.",
    ),
    ProtectionItem(
        "The fact that you use Void",
        "Void appears on your phone like any other app. Anyone who looks can see it " +
            "is installed. In some places, that alone attracts attention.",
    ),
    ProtectionItem(
        "Notifications, if you turn them on",
        "Google can see that your phone was pinged, and when — not by whom or about " +
            "what. Over months, that is a pattern. Notifications are off until you turn " +
            "them on.",
    ),
    ProtectionItem(
        "Someone watching both ends",
        "An adversary who can watch your internet connection and your contact's, over " +
            "a long time, may be able to tell you are talking. Void makes this " +
            "expensive. It does not make it impossible.",
    ),
    ProtectionItem(
        "Anything you tell someone else",
        "The person you message can screenshot it, repeat it, or hand over their phone.",
    ),
)

@Composable
fun ProtectionScreen(onAcknowledge: () -> Unit) {
    val scrollState = rememberScrollState()
    val scrolledToEnd = scrollState.value >= (scrollState.maxValue - 4).coerceAtLeast(0)

    Column(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.weight(1f).verticalScroll(scrollState).padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(28.dp),
        ) {
            Spacer(Modifier.height(24.dp))
            Text("What Void protects, and what it doesn't", style = MaterialTheme.typography.headlineMedium)
            Text(
                "Please read this. It is the honest version, and it is short.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ProtectionSection("What Void protects", PROTECTS)
            ProtectionSection("What Void does not protect", DOES_NOT_PROTECT)
            Spacer(Modifier.height(8.dp))
        }

        Divider()
        Button(
            onClick = onAcknowledge,
            enabled = scrolledToEnd,
            modifier = Modifier.fillMaxWidth().padding(20.dp),
        ) {
            Text(if (scrolledToEnd) "I've read this" else "Scroll to the end")
        }
    }
}

@Composable
private fun ProtectionSection(title: String, items: List<ProtectionItem>) {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Text(title, style = MaterialTheme.typography.titleLarge)
        items.forEach { item ->
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(item.title, style = MaterialTheme.typography.titleSmall)
                Text(item.body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun DeviceLossScreen(onSetUpRecovery: () -> Unit, onAcceptTheRisk: () -> Unit) {
    var understood by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text("If you lose this phone", style = MaterialTheme.typography.headlineMedium)
        Text(VoidCore.textDeviceLossWarning(), style = MaterialTheme.typography.bodyLarge)
        Text(
            "This is not a limitation we can remove. Your keys never leave this device, " +
                "which is the reason nobody else can read your messages — and the reason " +
                "nobody, including us, can get them back for you.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(0.dp),
        ) {
            androidx.compose.foundation.layout.Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Switch(checked = understood, onCheckedChange = { understood = it })
                Text(
                    "I understand that losing this phone means losing my messages and my identity.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        Spacer(Modifier.weight(1f))

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onSetUpRecovery, enabled = understood, modifier = Modifier.fillMaxWidth()) {
                Text("Set up a recovery file")
            }
            // Both options are real choices and are presented as such —
            // non-negotiable #8: no dark patterns on security choices.
            OutlinedButton(onClick = onAcceptTheRisk, enabled = understood, modifier = Modifier.fillMaxWidth()) {
                Text("Continue without one")
            }
        }
    }
}

private enum class OnboardingStep { PROTECTION, DEVICE_LOSS, DONE }

@Composable
fun OnboardingFlow(onFinished: () -> Unit) {
    var step by remember { mutableStateOf(OnboardingStep.PROTECTION) }
    when (step) {
        OnboardingStep.PROTECTION -> ProtectionScreen(onAcknowledge = { step = OnboardingStep.DEVICE_LOSS })
        OnboardingStep.DEVICE_LOSS -> DeviceLossScreen(
            onSetUpRecovery = { step = OnboardingStep.DONE },
            onAcceptTheRisk = { step = OnboardingStep.DONE },
        )
        OnboardingStep.DONE -> androidx.compose.runtime.LaunchedEffect(Unit) { onFinished() }
    }
}
