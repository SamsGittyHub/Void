#!/usr/bin/env bash
# Cross-compiles void-jni for Android and places the resulting .so files
# where android/app's Gradle build expects them. void-jni is the JNI-ABI
# crate (Java_app_void_VoidCore_* symbols) that wraps void-ffi's C ABI for
# Kotlin — see crates/void-jni/src/lib.rs and docs/DECISIONS.md's D-023.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to your NDK install (e.g. via 'sdkmanager --install \"ndk;27.0.0\"')}"

# arm64-v8a and x86_64 only — see android/app/build.gradle.kts's comment on
# why armeabi-v7a (32-bit ARM) is not part of this build.
#
# Two parallel indexed arrays rather than one associative array: macOS ships
# bash 3.2 as /bin/bash (no `declare -A` support, licensing-frozen since
# 2007), and this script needs to run under whatever `bash` a developer's
# `PATH` finds, not just a Homebrew one.
RUST_TARGETS=(aarch64-linux-android x86_64-linux-android)
ABIS=(arm64-v8a x86_64)

API_LEVEL=30 # NFR-COMP-02

for i in "${!RUST_TARGETS[@]}"; do
  rust_target="${RUST_TARGETS[$i]}"
  abi="${ABIS[$i]}"
  rustup target add "$rust_target" >/dev/null 2>&1 || true

  toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
  cc="$toolchain/${rust_target}${API_LEVEL}-clang"
  export CARGO_TARGET_$(echo "$rust_target" | tr '[:lower:]-' '[:upper:]_')_LINKER="$cc"
  export CC_$(echo "$rust_target" | tr '-' '_')="$cc"
  # cc-rs (rusqlite's bundled-sqlite build script) looks for a target-prefixed
  # `ar`; NDK 23+ only ships the unified `llvm-ar`, not that binutils-style name.
  export AR_$(echo "$rust_target" | tr '-' '_')="$toolchain/llvm-ar"

  echo "Building void-jni for $rust_target ($abi)…"
  cargo build -p void-jni --release --target "$rust_target"

  out_dir="android/app/src/main/jniLibs/$abi"
  mkdir -p "$out_dir"
  cp "target/$rust_target/release/libvoid_jni.so" "$out_dir/libvoid_jni.so"
done

echo "Done: android/app/src/main/jniLibs/{arm64-v8a,x86_64}/libvoid_jni.so"
