# VoidCore's `external fun` declarations are resolved by the JNI shim in
# void-ffi at runtime by name — R8 must not rename, inline, or strip them.
-keep class app.void.VoidCore {
    native <methods>;
}

# void-jni builds its compound results by class name and constructor signature
# (`find_and_new_object`), which R8 cannot see. Renaming a class or stripping
# its constructor would make every such call return null — every tick would
# read as offline — so keep them exactly as written.
-keep class app.void.NativeInviteResult { <init>(...); }
-keep class app.void.NativeOpenResult { <init>(...); }
-keep class app.void.NativeStartResult { <init>(...); }
-keep class app.void.NativeSendResult { <init>(...); }
-keep class app.void.NativeTickResult { <init>(...); }
