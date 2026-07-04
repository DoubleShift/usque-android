# ProGuard / R8 rules for Usque VPN Re
#
# Debug builds (default for this workflow) do not use ProGuard.
# These rules apply only to release builds (isMinifyEnabled = true).

# Keep the gomobile-generated usqueandroid package.
# These classes are accessed reflectively / via JNI from the Kotlin side.
-keep class usqueandroid.** { *; }

# Keep Go runtime classes used by gomobile.
-keep class go.** { *; }

# Keep VpnService subclass (instantiated by the system).
-keep class re.abobo.usquevpn.UsqueVpnService { *; }

# Kotlin metadata
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClass
-keepclassmembers class kotlin.Metadata { *; }
