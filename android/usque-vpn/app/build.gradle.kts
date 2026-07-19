plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "re.abobo.usquevpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "re.abobo.usquevpn"
        minSdk = 24
        targetSdk = 34
        versionCode = 18
        versionName = "1.0.18-fix-tunnel"

        // ARM64 only — halves native lib size, covers all modern devices
        ndk {
            abiFilters += "arm64-v8a"
        }

        // Strip unused language resources (app only ships English UI text)
        resourceConfigurations += "en"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            // Sign with debug key so release APK is directly installable
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
    }
}

dependencies {
    // Usque Go library (compiled with gomobile, arm64 only)
    implementation(files("libs/usque.aar"))

    // Kotlin standard library
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.22")

    // AndroidX core — lightweight, only adds a few utility functions
    implementation("androidx.core:core-ktx:1.12.0")

    // RecyclerView (used by per-app selector)
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // NOTE: Material Components and AppCompat were removed to reduce memory.
    // - MainActivity extends android.app.Activity (not AppCompatActivity),
    //   so AppCompat is not needed.
    // - No Material widgets are used in any layout; all drawables are plain
    //   <shape>/<selector> XML. The theme was switched to a platform
    //   DeviceDefault theme (see values/themes.xml).
    // - AlertDialog is android.app.AlertDialog, not androidx/Material.
    // This saves ~2-3 MB of code memory (per-class tables, inflater
    // overhead, dex mmap) and slightly reduces Graphics memory.
}
