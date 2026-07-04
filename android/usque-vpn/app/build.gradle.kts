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
        versionCode = 13
        versionName = "1.0.13-info-panel"

        // ARM64 only — halves native lib size, covers all modern devices
        ndk {
            abiFilters += "arm64-v8a"
        }
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

    // AndroidX core
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")

    // Material Design (required by theme)
    implementation("com.google.android.material:material:1.11.0")

    // RecyclerView (used by per-app selector)
    implementation("androidx.recyclerview:recyclerview:1.3.2")
}
