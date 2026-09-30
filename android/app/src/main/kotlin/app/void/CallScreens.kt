package app.void

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * The call screen, the incoming-call sheet, and the disclosure a user reads
 * before a call connects.
 *
 * FR-UI-03 wants security state in plain language rather than iconography the
 * user has to learn. Two things follow from that here.
 *
 * **The delay is stated, not hidden.** A call over Tor runs about
 * three-quarters of a second each way — measured, see
 * `experiments/onion-call/RESULTS.md`. The mic is open both ways, so this is a
 * call; it is a call with noticeable lag, and a user who is told that adapts
 * while a user who is not assumes the app is broken.
 *
 * **The disclosure text comes from the core.** `CALL_DISCLOSURE` lives in
 * `void_proto::call` next to the behaviour it describes, so this file cannot
 * soften it and the Swift one cannot drift from it. It says what a call
 * actually costs — that the other person learns you are online, and that a
 * call's traffic shape is nothing like messaging's — and does not claim
 * location exposure, because media runs over onion services in both directions
 * and that claim would be false.
 */

/** A call waiting on the user reading the disclosure. */
data class PendingCall(
    val fingerprint: ByteArray,
    val isAnswering: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PendingCall) return false
        return fingerprint.contentEquals(other.fingerprint) && isAnswering == other.isAnswering
    }

    override fun hashCode(): Int =
        fingerprint.contentHashCode() * 31 + isAnswering.hashCode()
}

/** Where a call is in its life. */
enum class CallPhase {
    /** Our onion service is going up. */
    PUBLISHING,

    /** The offer is on its way; waiting for them. */
    RINGING,

    /** They are calling us. */
    INCOMING,

    /** Answered; waiting for the first authenticated audio. */
    CONNECTING,

    /** Audio is flowing. */
    ACTIVE,
}

/** Which end of a call this device is. */
enum class CallRole { CALLER, CALLEE }

/**
 * One call, as the UI needs it. The media secret is deliberately not here: it
 * goes straight from the engine to the media connection and is never part of
 * what a screen can render.
 */
data class CallSession(
    val fingerprint: ByteArray,
    val callId: ByteArray,
    val role: CallRole,
    val phase: CallPhase,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CallSession) return false
        return fingerprint.contentEquals(other.fingerprint) && callId.contentEquals(other.callId) &&
            role == other.role && phase == other.phase
    }

    override fun hashCode(): Int = (fingerprint.contentHashCode() * 31 + callId.contentHashCode()) * 31 + phase.ordinal
}

@Composable
fun CallScreen(
    contactName: String,
    phase: CallPhase,
    isMuted: Boolean,
    onMuteChange: (Boolean) -> Unit,
    onHangUp: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(contactName, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.size(8.dp))
        Text(
            statusLine(phase),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.size(40.dp))

        if (phase == CallPhase.ACTIVE) {
            // Mute, not push-to-talk: the microphone is open both ways for the
            // whole call. Muting stops the microphone, not the emission —
            // silence frames go out on the same cadence, so a muted call and a
            // talking one are the same shape on the wire.
            Box(
                modifier = Modifier
                    .size(160.dp)
                    .clip(CircleShape)
                    .background(
                        if (isMuted) MaterialTheme.colorScheme.surfaceVariant
                        else MaterialTheme.colorScheme.primary
                    )
                    .pointerInput(Unit) {
                        detectTapGestures(onTap = { onMuteChange(!isMuted) })
                    }
                    .testTag("muteButton"),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    if (isMuted) "Muted" else "Mute",
                    color = if (isMuted) MaterialTheme.colorScheme.onSurfaceVariant
                    else MaterialTheme.colorScheme.onPrimary,
                )
            }

            Spacer(Modifier.size(24.dp))
            // Not an apology — an instruction. Users who know about the lag
            // pause for it; users who do not talk over each other and conclude
            // the app is broken.
            Text(
                "About a second of delay each way — leave a beat before you reply.",
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("callLatencyExplanation"),
            )
        }

        Spacer(Modifier.weight(1f))

        Button(
            onClick = onHangUp,
            modifier = Modifier.fillMaxWidth().testTag("endCallButton"),
        ) {
            Text(if (phase == CallPhase.ACTIVE) "End" else "Cancel")
        }
    }
}

@Composable
fun IncomingCallScreen(
    contactName: String,
    isVerified: Boolean,
    onAnswer: () -> Unit,
    onDecline: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(contactName, style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.size(6.dp))
        Text("wants to talk", style = MaterialTheme.typography.bodyMedium)

        Spacer(Modifier.size(16.dp))
        // FR-UI-03: trust state as a sentence, not a badge. Worth saying out
        // loud here specifically, because a voice feels like proof of identity
        // and is not one.
        Text(
            if (isVerified) "You've checked their security code."
            else "You haven't checked their security code yet. A voice can be imitated.",
            style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
            modifier = Modifier.testTag("incomingCallTrustNote"),
        )

        Spacer(Modifier.weight(1f))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedButton(
                onClick = onDecline,
                modifier = Modifier.weight(1f).testTag("declineCallButton"),
            ) {
                Text("Decline")
            }
            Button(
                onClick = onAnswer,
                modifier = Modifier.weight(1f).testTag("answerCallButton"),
            ) {
                Text("Answer")
            }
        }
    }
}

private fun statusLine(phase: CallPhase): String = when (phase) {
    CallPhase.PUBLISHING -> "Setting up a private connection…"
    // Honest about the wait: the offer travels through their mailbox, and that
    // takes up to a minute (D-028).
    CallPhase.RINGING -> "Ringing. It can take up to a minute to reach them."
    CallPhase.INCOMING -> "Incoming"
    CallPhase.CONNECTING -> "Connecting…"
    CallPhase.ACTIVE -> "Connected over Tor"
}

/**
 * Shown before a call connects — placing one or answering one.
 *
 * The body is [VoidCore.textCallDisclosure], fetched rather than retyped so it
 * cannot be softened here. Per non-negotiable #8 the option states its cost,
 * and per FR-UI-03 it does so in sentences rather than a warning triangle
 * nobody reads.
 *
 * The confirming button is not "OK". Someone who has read this is agreeing to
 * something specific, so the button says what.
 */
@Composable
fun CallDisclosureScreen(
    contactName: String,
    isAnswering: Boolean,
    onContinue: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text(
            if (isAnswering) "Before you answer" else "Before you call",
            style = MaterialTheme.typography.headlineSmall,
        )

        Column(modifier = Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Text(
                VoidCore.textCallDisclosure(),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag("callDisclosureText"),
            )
        }

        Text(
            if (isAnswering) "Answering tells $contactName you're here."
            else "Calling tells $contactName you're here.",
            style = MaterialTheme.typography.bodySmall,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.weight(1f).testTag("callDisclosureCancel"),
            ) {
                Text("Not now")
            }
            Button(
                onClick = onContinue,
                modifier = Modifier.weight(1f).testTag("callDisclosureContinue"),
            ) {
                Text(if (isAnswering) "Answer anyway" else "Call anyway")
            }
        }
    }
}
