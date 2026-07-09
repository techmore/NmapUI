# SwiftUI Migration Plan

Goal: move the macOS experience toward a SwiftUI-first shell while keeping the existing web frontend and backend behavior intact until parity is proven.

## Backend Orchestration Plan

This is the concrete migration path for moving backend orchestration into Swift without breaking the current product:

1. Swift launcher and runtime contract
   - Keep Node as the backend runtime for now.
   - Make Swift the only code that starts, stops, restarts, and health-checks the runtime on macOS.
   - Keep the loopback port and readiness URL stable.

2. Swift-owned process and preference state
   - Keep runtime configuration in Swift preferences.
   - Use structured runtime settings instead of a freeform shell string.
   - Preserve backward compatibility with legacy user defaults until migration is complete.

3. Swift-owned backend services
   - Move launch-at-login, open-browser, port-check, and restart behavior into Swift where possible.
   - Keep the Node backend focused on scan/report generation and the web UI contract.

4. Gradual Node reduction
   - Replace backend shell helpers with direct process execution first.
   - Move remaining orchestration helpers into Swift only after the Swift launcher and settings remain stable across eval runs.
   - Do not rewrite Nmap scanning semantics until the orchestration boundary is stable.

5. Final split decision
   - Keep Node if it remains the clearest owner for scan/report logic.
   - Move more runtime responsibilities into Swift if parity proves that the Swift path is stable and easier to maintain.

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

1. Finish the Swift launcher so it owns startup, readiness, restart, and browser auto-open.
2. Keep preferences and menu bar state in Swift, with structured runtime settings and legacy compatibility.
3. Leave the Node backend in place for scan/report generation until the Swift orchestration path is stable.
4. Replace remaining shell-backed helper scripts only after the Swift shell and startup flow are stable.
5. Keep the web frontend untouched until the Swift shell can launch, persist settings, and reopen reliably.

## Verification Gates

- `./packaging/macos/bundle.sh` builds successfully.
- `./scripts/nightly_product_eval.sh --run` completes successfully.
- `curl http://127.0.0.1:9000/api/app-identity` returns the expected app identity.
- The menu bar app opens the browser automatically when ready.
- A first scan can still be started and completed from the existing UI.
- The Swift launcher can restart the runtime without shelling out except where explicit shell behavior is required.
- Structured runtime settings survive app relaunch and preserve legacy users' existing configurations.

## Execution Checklist

1. Keep the current Swift launcher/runtime boundary stable.
   - Owner: `RuntimeLifecycleController`, `StartupCoordinator`, `ProcessLauncher`
   - Done when launch, restart, timeout, and browser auto-open still pass nightly eval.

2. Finish migrating runtime configuration persistence.
   - Owner: `PreferencesStore`, `PreferencesView`
   - Done when structured executable + arguments settings are the only active path and legacy keys are only compatibility bridges.

3. Continue reducing backend shell helpers.
   - Owner: `server.js`
   - Done when report generation and runtime utilities use direct process execution wherever shell expansion is not required.
   - Status: complete for the current runtime surface; `server.js` now uses `execFile`/`spawn` for the remaining process launches.

4. Decide whether Node stays the orchestration host.
   - Owner: migration review, after the previous slices are stable.
   - Done when we can prove whether Node remains the best owner for scan/report semantics or whether a further Swift extraction is justified.

## Orchestration Decision

Current recommendation: keep Node as the orchestration host for scan/report semantics for now.

Why:

- Node still owns the scan lifecycle, report generation, socket events, history, auto-scan, and Google Drive status plumbing.
- Swift already owns launcher lifecycle, readiness polling, restart, browser open, and preference persistence.
- The remaining Node surface is still the product runtime, not just incidental glue.

First extraction candidate:

- Add a Swift-native readiness and app-identity bridge only if it improves startup reliability without duplicating the Node scan/runtime contract.
- Treat that as a bridge experiment, not a wholesale runtime migration.
- Keep it behind the existing loopback contract until parity is proven.

Decision gate for the next slice:

- If a Swift-owned bridge can replace one Node handshake without changing scan/report behavior, move it.
- If not, keep Node in place and continue tightening the Swift shell and backend process boundaries.

Next implementation slice:

1. Add a Swift-owned readiness check helper that can validate the loopback runtime state independently of the web UI.
2. Keep `/api/app-identity` in Node for now, but introduce a Swift-side probe path that can prove the runtime is reachable before the browser opens.
3. Use the existing nightly eval loop to confirm that the bridge does not change startup timing, browser auto-open, or scan initiation.

Bridge status:

- `RuntimeEndpoints.readinessURL` now points at `/api/app-identity` so the Swift launcher can prove the Node runtime is reachable with an existing contract.
- `RuntimeBridge` now probes TCP reachability before it polls the identity endpoint, which makes startup failures easier to distinguish from contract failures.
- `RuntimeIdentity` is now a typed Swift representation of the Node identity payload, so the bridge is explicit instead of being a generic JSON poll.
- `RuntimeBridge` now owns the typed readiness probe used by the Swift launcher.
- The native shell now surfaces the resolved backend identity in session state, so the Swift side owns the user-facing view of the runtime contract.
- This is a bridge experiment, not a replacement for the Node backend runtime.

## Backend Replacement Slice

The backend replacement plan is now concrete enough to implement incrementally:

1. Keep the macOS launch path and startup metadata in Swift.
2. Treat `runtime-identity.json` as the first shared contract file written by Swift and read by Node.
3. Keep Node as the scan/report runtime until an equivalent Swift-owned service is ready.
4. Move helper-style integrations behind Swift-owned stores or facades before touching scan semantics.
5. Replace runtime endpoints one contract at a time, preserving the existing loopback URLs and nightly eval checks.

Current implementation slice:

- `RuntimeMetadataStore` centralizes runtime identity file persistence for the native launcher.
- `server.js` reads the launcher-written runtime identity file when it is present and falls back to the legacy identity payload otherwise.
- This narrows Node's role in the app identity handshake without changing the scan/report behavior.

Current helper contract slice:

- `RuntimeCapabilities` centralizes startup-visible helper availability for the native launcher.
- `RuntimeMetadataStore` now persists `runtime-capabilities.json` alongside `runtime-identity.json`.
- The Google Drive helper is still executed separately today, but its availability is now a shared startup contract that Swift can own and refresh when runtime identity resolves. The native shell shows that state directly in its header so the contract is user-visible.
