plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    // Not "app.void": AGP's `namespace` names the package it generates R.java
    // and BuildConfig.java into, and those are compiled as plain Java, where
    // `void` is a reserved keyword — `package app.void;` does not parse.
    // Kotlin has no such reservation, so every hand-written source file below
    // still declares `package app.void` (see e.g. VoidCore.kt) without
    // conflict, which is what keeps the JNI symbol names in
    // crates/void-jni/src/lib.rs (`Java_app_void_VoidCore_*`, derived from the
    // compiled class's actual package) correct with no changes on that side.
    namespace = "app.voidmessenger"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.void"
        minSdk = 30 // NFR-COMP-02
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // The two ABIs `scripts/build_android.sh` cross-compiles void-jni
        // for. armeabi-v7a is deliberately absent: StrongBox (NFR-COMP-02's
        // preferred key backing) does not exist on any device old enough to
        // need 32-bit ARM support.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // libvoid_jni.so per ABI, placed here by scripts/build_android.sh —
    // never hand-copied; see that script's header for why.
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    packaging {
        // FR-DIST-06: a direct APK build with reproducible core hashes.
        // Uncompressed native libraries make the packaged .so byte-for-byte
        // comparable to the standalone cross-compiled artifact
        // scripts/check_reproducible.sh-style tooling would hash — a
        // compressed one is not, because zip compression is not guaranteed
        // deterministic across toolchains.
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // FR-DISC-01's QR path. zxing-android-embedded wraps CameraX + ZXing
    // core with the permission/lifecycle glue already handled — pulling
    // core, camerax, and the scanning glue in separately would be three
    // dependencies doing the job zxing-android-embedded already does as
    // one, reviewed, widely-used library (no analytics, no network access
    // of its own, matching NFR-SEC-07's bar for the trusted-adjacent path).
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.3")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}
