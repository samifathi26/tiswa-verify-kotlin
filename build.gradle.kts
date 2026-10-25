// Verify with Tiswa for Android: PKCE, the Tiswa sheet in a Custom Tab, and the return to your
// app (RFC 8252). Published free through JitPack from the public verify-kotlin repository.
plugins {
    id("com.android.library") version "9.4.0"
    `maven-publish`
}

group = "app.tiswa"
version = "0.1.0"

android {
    namespace = "app.tiswa.verify"
    compileSdk = 36
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions { unitTests.isReturnDefaultValues = true }
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    implementation("androidx.browser:browser:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "app.tiswa"
            artifactId = "verify"
            afterEvaluate { from(components["release"]) }
        }
    }
}
