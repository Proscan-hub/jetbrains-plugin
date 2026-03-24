plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.20"
    id("org.jetbrains.intellij") version "1.16.1"
}

group = "com.proscan"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.code.gson:gson:2.10.1")
}

intellij {
    version.set("2023.3")
    type.set("IC")
}

tasks {
    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }

    patchPluginXml {
        sinceBuild.set("233")
        untilBuild.set("251.*")
        changeNotes.set("""
            <ul>
                <li>Initial release</li>
                <li>SAST scanning from JetBrains IDEs</li>
                <li>Inline annotations with severity-based highlighting</li>
                <li>Findings tool window grouped by severity</li>
                <li>Quick-fix intentions with autofix suggestions</li>
                <li>OAuth2/OIDC SSO authentication</li>
                <li>API key authentication</li>
                <li>Status bar widget showing connection state</li>
            </ul>
        """)
    }

    buildSearchableOptions {
        enabled = false
    }
}
