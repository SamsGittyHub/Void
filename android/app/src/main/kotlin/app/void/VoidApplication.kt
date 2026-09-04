package app.void

import android.app.Application

/**
 * Loads `libvoid_ffi.so` once for the process. [VoidCore]'s own `init` block
 * does this too, but doing it here as well means a load failure surfaces at
 * app start rather than at the first screen that happens to touch the core.
 */
class VoidApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Touch VoidCore now so `System.loadLibrary` runs during startup,
        // not on first use from a screen.
        VoidCore.recordSize()
    }
}
