#!/usr/bin/env bash
# Runs the Android app's JNI wrapper (VoidCore.kt, Engine.kt) on a desktop JVM
# against the real Rust core, through void-jni built for this machine (D-029).
#
# Every call crosses the real JNI shim, so a wrong `external fun` signature is
# an UnsatisfiedLinkError and a wrong result-class constructor a null result —
# mistakes that compile cleanly and only fail at runtime on a phone.
#
# Needs a JDK 17+ (JAVA_HOME). Uses the Android project's Gradle wrapper.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building void-jni for this machine…"
cargo build -q -p void-jni

echo "Running the Kotlin wrapper against it…"
cd tools/app-bindings/kotlin
../../../android/gradlew --no-daemon -q run
