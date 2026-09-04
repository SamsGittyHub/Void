plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    // Kotlin 2.0+ moved Compose's compiler out of the Kotlin compiler itself
    // and into this plugin; composeOptions { kotlinCompilerExtensionVersion }
    // (the pre-2.0 way of pinning it) no longer applies.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
