# Native Shell Strategy

## Decision

This project is now targeting macOS first, so a Swift-based desktop app is on the table.

## Recommended Direction

Keep Nmap as the external scanning engine and move the app toward a macOS-native desktop shell:

- Use Swift/AppKit or SwiftUI for the native shell.
- Keep the scan orchestration and real-time UI behavior, but move the runtime into a packageable desktop app.
- Preserve the current Nmap subprocess model rather than trying to reimplement scanner logic in the app layer.

For a macOS-only target, Swift is the more natural choice than a web-shell wrapper.

## Why Swift Now Makes Sense

- Native macOS look and behavior.
- Better fit for menu bar apps and system integration.
- No need to carry cross-platform abstraction when macOS is the only target.
- Nmap still runs externally, so the app layer can stay focused on orchestration and UI.

## Migration Shape

1. Keep the existing Nmap execution, reporting, and settings logic intact.
2. Move the UI into a desktop shell that can launch a local runtime.
3. Treat Nmap as an installed dependency, not an embedded library.
4. Keep scan state, logs, and report generation accessible through the desktop shell.
5. Replace platform-specific packaging last, after the app behavior is stable.

## Current State

The repository already contains desktop-oriented packaging work and a web-first runtime. The new `packaging/macos/` scaffold is the starting point for consolidating that runtime into a macOS-native app.
