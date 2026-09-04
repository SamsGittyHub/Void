# VoidCore's `external fun` declarations are resolved by the JNI shim in
# void-ffi at runtime by name — R8 must not rename, inline, or strip them.
-keep class app.void.VoidCore {
    native <methods>;
}
