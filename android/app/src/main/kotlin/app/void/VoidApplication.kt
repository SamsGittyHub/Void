package app.void

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where launch has got to. */
sealed class LaunchPhase {
    data object Opening : LaunchPhase()
    class Ready(val state: AppState) : LaunchPhase()
    class Failed(val message: String) : LaunchPhase()
}

/**
 * Owns the engine for the life of the process.
 *
 * It used to live in `MainActivity`, created in a `remember` and closed in
 * `onDestroy` — so rotating the screen destroyed the engine and, before
 * persistence, generated a new identity every time. Here it survives any
 * number of activities.
 */
class VoidApplication : Application() {
    /** Main-thread scope for the app's lifetime; engine work hops to [engineDispatcher]. */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** The one thread every engine call runs on. */
    val engineDispatcher = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "void-core").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    var phase by mutableStateOf<LaunchPhase>(LaunchPhase.Opening)
        private set

    override fun onCreate() {
        super.onCreate()
        // Load the native library now, so a failure shows at launch rather
        // than on the first screen that touches the core.
        VoidCore.recordSize()
        open()
    }

    /**
     * Release this device's key and open its engine, off the main thread:
     * opening derives and checks keys, and the Keystore call can take a moment.
     */
    private fun open() {
        phase = LaunchPhase.Opening
        appScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val opened = KeyVault.openOrCreate(this@VoidApplication)
                    // noBackupFilesDir: app-private and never in a backup (FR-STOR-05).
                    val engine = Engine.open(
                        File(noBackupFilesDir, "data"),
                        opened.kek,
                        opened.backing,
                        System.currentTimeMillis(),
                    )
                    Triple(engine, opened.backing, engine.fingerprintWords)
                }
            }
            phase = result.fold(
                onSuccess = { (engine, backing, words) ->
                    LaunchPhase.Ready(AppState(this@VoidApplication, engine, backing, words, appScope, engineDispatcher))
                },
                onFailure = { error ->
                    LaunchPhase.Failed(
                        if (error is VoidException && error.status == VoidStatus.LOCKED) {
                            // Never papered over by making a new identity: that
                            // would silently replace the user's, and every
                            // contact would see a stranger.
                            "This phone's key no longer opens Void's data. Nothing has been changed or replaced."
                        } else {
                            "Void couldn't open its data on this phone."
                        },
                    )
                },
            )
        }
    }
}
