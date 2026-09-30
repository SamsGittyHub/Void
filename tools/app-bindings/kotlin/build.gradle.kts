// Runs the Android app's JNI wrapper — VoidCore.kt, Engine.kt, RelayConfig.kt,
// which touch no Android API — on a desktop JVM, against the real Rust core
// through void-jni built for this machine. See scripts/check_android_bindings.sh.
plugins {
    kotlin("jvm") version "2.0.21"
    application
}

val repo: File = rootDir.resolve("../../..").canonicalFile

sourceSets {
    main {
        kotlin.srcDir(repo.resolve("android/app/src/main/kotlin"))
        kotlin.include("app/void/VoidCore.kt", "app/void/Engine.kt", "app/void/RelayConfig.kt", "app/void/JniCheck.kt")
    }
}

application {
    mainClass.set("app.void.JniCheckKt")
    applicationDefaultJvmArgs = listOf("-Djava.library.path=${repo.resolve("target/debug")}")
}
