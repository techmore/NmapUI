# SwiftUI Migration Plan

Goal: move the macOS experience toward a SwiftUI-first shell while keeping the existing web frontend and backend behavior intact until parity is proven.

## Current State

- The menu bar app shell already exists in Swift under `packaging/macos/Sources/NmapUIApp/`.
- The Google Drive helper path is now native Swift-first through `GoogleDriveHelper`.
- The nightly validation loop runs without Python in the active path.
- The old Docker packaging path and the old Python helper file have been removed from the active runtime path.

## Non-Negotiables

- Keep the menu bar icon and native macOS app feel.
- Keep the web frontend available during the migration.
- Keep the backend behavior stable while implementation details move.
- Keep the fixed loopback port behavior stable for the launcher.

## Migration Phases

1. Audit Python usage
   - Complete for the active runtime path.
   - Any remaining Python artifacts should be treated as legacy, archived, or test-only until proven otherwise.

2. SwiftUI app shell
   - Build a native SwiftUI shell for the menu bar app, preferences, and onboarding.
   - Preserve the current open-on-launch and auto-open browser behavior.
   - Keep the web frontend as the primary scan/report surface for now.

3. Swift launcher and preferences
   - Move startup, restart, port checks, and settings persistence into Swift.
   - Keep the runtime contract identical until the UI is fully stable.

4. Replace Python glue
   - Convert any remaining deployment helpers and maintenance scripts one by one.
   - Keep the backend observable behavior unchanged while swapping implementations.

5. Parity validation
   - Verify scan start, scan completion, reports, and local UI behavior.
   - Verify launch-at-login, restart, timeout handling, and browser auto-open.
   - Verify the nightly eval loop after each migration slice.

## Parity Checks

- App launches from the macOS bundle.
- Menu bar icon appears.
- Browser opens automatically after readiness.
- `http://127.0.0.1:9000` stays the default UI entrypoint.
- First scan completes successfully.
- Reports and settings still persist correctly.

## Recommended First Implementation Slice

1. Finish the Swift launcher so it owns startup, readiness, and browser auto-open.
2. Move preferences and menu bar state into the Swift shell without changing scan behavior.
3. Replace any remaining legacy helper scripts only after the shell and startup flow are stable.
4. Keep the web frontend untouched until the Swift shell can launch, persist settings, and reopen reliably.

## Verification Gates

- `./packaging/macos/bundle.sh` builds successfully.
- `./scripts/nightly_product_eval.sh --run` completes successfully.
- `curl http://127.0.0.1:9000/api/app-identity` returns the expected app identity.
- The menu bar app opens the browser automatically when ready.
- A first scan can still be started and completed from the existing UI.
