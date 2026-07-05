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

# Keep Activities referenced from AndroidManifest.xml.
-keep class re.abobo.usquevpn.MainActivity { *; }
-keep class re.abobo.usquevpn.AppSelectorActivity { *; }

# Kotlin metadata
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClass
-keepclassmembers class kotlin.Metadata { *; }

# Suppress common gomobile/AndroidX warnings that do not affect runtime.
-dontwarn usqueandroid.**
-dontwarn go.**
-dontwarn android.window.BackEvent

# Allow R8 to remove more unused code by not keeping generic exception stack traces.
-optimizations !code/simplification/cast
