package app.void

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * The screens where PRD non-negotiable #8 applies: "No dark patterns on
 * security choices. Push, retention, and duress settings are presented
 * honestly, with the costs of each option stated."
 *
 * These mirror the iOS screens in `ios/Void/SecuritySettingsViews.swift`
 * requirement for requirement. Where the two platforms show the user words that
 * the PRD specifies, both fetch them from [VoidCore] rather than holding their
 * own copy.
 */

/** FR-NOTIF-04 and FR-UI-06: push is off by default, and the choice is even. */
@Composable
fun NotificationSettings(
    pushEnabled: Boolean,
    onPushChanged: (Boolean) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Notifications", style = MaterialTheme.typography.headlineSmall)

        // FR-UI-06: both options render through the same composable, so they
        // cannot drift apart in visual weight. There is no prominent "Enable"
        // and greyed-out "Not now".
        ChoiceCard(
            title = "Notifications off",
            detail = "Messages arrive only when you open Void. Nothing tells Google that your " +
                "phone received anything.",
            cost = "You will not know a message arrived until you look.",
            selected = !pushEnabled,
            onSelect = { onPushChanged(false) },
        )
        ChoiceCard(
            title = "Notifications on",
            detail = "Void's server pings your phone when something is waiting. The ping " +
                "carries no sender, no preview, and nothing about the message.",
            cost = "Google can see that your phone was pinged, and when. Over months that is " +
                "a pattern, and it is available to anyone who can compel Google.",
            selected = pushEnabled,
            onSelect = { onPushChanged(true) },
        )

        Text(
            "There is no right answer here. If you are worried about a government asking " +
                "Google about your phone, leave this off. Otherwise, on is reasonable.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun ChoiceCard(
    title: String,
    detail: String,
    cost: String,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    OutlinedCard(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            RadioButton(selected = selected, onClick = onSelect)
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(detail, style = MaterialTheme.typography.bodyMedium)
                Text(
                    cost,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/** FR-STOR-04: shortest first, each with its consequence stated. */
@Composable
fun RetentionSettings(
    policy: RetentionPolicy,
    onPolicyChanged: (RetentionPolicy) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Delete messages after", style = MaterialTheme.typography.headlineSmall)

        RetentionPolicy.ordered.forEach { option ->
            ChoiceCard(
                title = option.label,
                detail = option.consequence,
                cost = "",
                selected = policy == option,
                onSelect = { onPolicyChanged(option) },
            )
        }

        Text(
            "Shortening this applies to messages you already have. Lengthening it does not " +
                "bring back messages that were already deleted, and does not extend ones that " +
                "are already counting down.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

/** FR-STOR-02 and FR-UI-04: duress setup, with a typed confirmation. */
@Composable
fun DuressSetup(onConfirm: (String) -> Unit) {
    var pin by remember { mutableStateOf("") }
    var phrase by remember { mutableStateOf("") }

    // Fetched from the core so the wording is identical to iOS and to the
    // sentence PRD §7.4.1 requires.
    val disclosure = remember { VoidCore.textDuressDisclosure() }
    val requiredPhrase = remember { VoidCore.textDuressConfirmation() }

    val phraseMatches = phrase.trim().equals(requiredPhrase, ignoreCase = true)
    val canConfirm = pin.length >= 4 && phraseMatches

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Duress PIN", style = MaterialTheme.typography.headlineSmall)

        Card {
            Text(
                disclosure,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        Text(
            "A duress PIN looks like a normal PIN. Entering it at the lock screen destroys " +
                "the key that protects everything on this phone, and shows an empty Void as " +
                "if you had just installed it.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            "It takes less than half a second and cannot be stopped once started. There is no " +
                "way to undo it and no way for us to recover anything.",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedTextField(
            value = pin,
            onValueChange = { pin = it },
            label = { Text("Duress PIN") },
            supportingText = {
                Text("Must be different from your normal PIN, and memorable under pressure.")
            },
            modifier = Modifier.fillMaxWidth(),
        )

        // FR-UI-04: typed, not tapped. A tap is muscle memory; typing is a
        // decision.
        Text("Type: $requiredPhrase", style = MaterialTheme.typography.labelMedium)
        OutlinedTextField(
            value = phrase,
            onValueChange = { phrase = it },
            label = { Text("Confirmation phrase") },
            isError = phrase.isNotEmpty() && !phraseMatches,
            modifier = Modifier.fillMaxWidth(),
        )

        Button(
            onClick = { onConfirm(pin) },
            enabled = canConfirm,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Set duress PIN")
        }
    }
}

/** NFR-COMP-02: the StrongBox / TEE difference, surfaced rather than hidden. */
@Composable
fun KeyStorageScreen(backing: VaultBacking) {
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("How your keys are protected", style = MaterialTheme.typography.headlineSmall)
        Card {
            Text(
                backing.userDescription,
                modifier = Modifier.padding(16.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        // FR-ID-02a, made user-facing: the honest claim is "not extractable
        // from a locked phone", never "never in memory".
        Text(
            "Your keys cannot be copied off a locked phone. While Void is unlocked and in " +
                "use, they are in the phone's memory like any other app's data — which is why " +
                "a phone taken while unlocked, or one with spyware on it, is outside what " +
                "Void can protect.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

/** FR-DISC-05: a changed key blocks messaging; the composer is replaced. */
@Composable
fun ComposerArea(
    trust: TrustState,
    draft: String,
    onDraftChanged: (String) -> Unit,
    onSend: () -> Unit,
    /** The attach buttons, ahead of the text field; nothing by default. */
    attachments: @Composable () -> Unit = {},
) {
    if (trust.canSend) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            attachments()
            OutlinedTextField(
                value = draft,
                onValueChange = onDraftChanged,
                placeholder = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            FilledIconButton(onClick = onSend, enabled = draft.isNotBlank()) {
                Text("→")
            }
        }
    } else {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "Messaging is paused",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.error,
            )
            Text(
                "Void will not send to this contact until you have checked their new security " +
                    "code through another channel.",
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
            )
        }
    }
}
