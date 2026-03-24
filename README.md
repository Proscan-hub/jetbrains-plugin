# Proscan JetBrains Plugin

Security scanning integration for IntelliJ IDEA, WebStorm, PyCharm, GoLand, and all JetBrains IDEs.

## Requirements

- A running [Proscan](https://proscan.one) instance on your network
- JetBrains IDE 2023.3 or newer

## Features

- Inline security annotations with severity-based highlighting
- Findings tool window grouped by severity
- Quick-fix intentions with autofix suggestions from the Proscan server
- Scan project or individual files from the Tools menu
- OAuth2/OIDC SSO authentication
- API key authentication
- Status bar widget showing connection state

## Setup

1. Install the plugin from [JetBrains Marketplace](https://plugins.jetbrains.com)
2. Go to **Settings > Tools > ProScan**
3. Enter your Proscan server URL
4. Enter your API token (generate one from Proscan Settings > API Tokens)
5. Click **Test Connection** to verify

## Building from Source

```bash
# Requires Java 17+ and Gradle
./gradlew buildPlugin
```

The built plugin will be in `build/distributions/`.

## Links

- Website: [proscan.one](https://proscan.one)
- Documentation: [Proscan-hub/docs](https://github.com/Proscan-hub/docs)
- Issues: [Report an issue](https://github.com/Proscan-hub/jetbrains-plugin/issues)

## License

MIT License — see [LICENSE](LICENSE) for details.
