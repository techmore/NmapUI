# Migration Checklist

This document tracks the final move from the legacy Node-hosted macOS runtime to the Swift-native app under `packaging/macos/`.

Goal:
- Keep the app runnable while the last legacy pieces are removed.
- Let Swift own launch, readiness, transport, scan state, and UI-facing runtime contracts.
- Remove Node from the macOS app path once parity is proven.

Primary references:
- [`server.js`](/Users/seandolbec/Projects/NmapUI/server.js)
- [`packaging/macos/Sources/NmapUIApp/AppDelegate.swift`](/Users/seandolbec/Projects/NmapUI/packaging/macos/Sources/NmapUIApp/AppDelegate.swift)
- [`packaging/macos/Sources/NmapUIApp/RuntimeBridge.swift`](/Users/seandolbec/Projects/NmapUI/packaging/macos/Sources/NmapUIApp/RuntimeBridge.swift)
- [`packaging/macos/Sources/NmapUIApp/ScanCoordinator.swift`](/Users/seandolbec/Projects/NmapUI/packaging/macos/Sources/NmapUIApp/ScanCoordinator.swift)
- [`packaging/macos/Sources/NmapUIApp/RuntimeMetadataStore.swift`](/Users/seandolbec/Projects/NmapUI/packaging/macos/Sources/NmapUIApp/RuntimeMetadataStore.swift)
- [`packaging/macos/Sources/NmapUIApp/RuntimeRequestDispatcher.swift`](/Users/seandolbec/Projects/NmapUI/packaging/macos/Sources/NmapUIApp/RuntimeRequestDispatcher.swift)

## Current State

Swift already owns the native shell and the launcher/runtime boundary. The remaining work is mainly legacy removal and parity hardening.

### Already Swift-owned

- [x] App launch and process lifecycle control.
- [x] Runtime readiness probing.
- [x] Runtime identity and capability persistence.
- [x] Scan execution and scan session state.
- [x] Bootstrap snapshot loading on launch.
- [x] Typed request dispatch for native runtime contracts.
- [x] Native Google Drive helper path.
- [x] Native runtime metadata stores.
- [x] Swift tests covering the current runtime contract and metadata behavior.

### Still legacy or partially bridged

- [ ] `server.js` remains the macOS host.
- [ ] Socket.IO is still part of the runtime transport on the Node path.
- [ ] Node still owns the browser-facing runtime surface for the legacy app.
- [ ] Node still contains helper glue for reports, history, scan orchestration, and Google Drive bridging.
- [ ] Node still serves static assets and report/history endpoints in the legacy host path.

## Final Migration Plan

### 1. Remove Node as the macOS host

- [ ] Stop using `server.js` to launch or host the macOS app.
  - Success means the macOS bundle starts from the Swift app entrypoint without depending on Node as the primary runtime host.
- [ ] Remove Node from the app startup, readiness, and restart path.
  - Success means Swift owns launch/restart and the runtime can be validated without Node-specific host behavior.

### 2. Remove the Socket.IO transport from the macOS path

- [ ] Replace the last live Socket.IO transport usage with the Swift request/event bridge.
  - Success means UI-facing runtime events are emitted from Swift only.
- [ ] Delete Node-side socket registration and broadcast paths that are no longer reachable.
  - Success means the legacy event router is gone, not just unused.

### 3. Remove legacy orchestration helpers

- [ ] Delete Node scan orchestration fallback code.
  - Success means quick scan, complete scan, dragnet scan, phase completion, and lifecycle transitions are all owned by Swift or by a single non-Node replacement path.
- [ ] Remove Node lifecycle broadcast helpers.
  - Success means scan start, progress, completion, and stop events come from Swift-emitted state.
- [ ] Remove helper glue that Swift already covers.
  - Includes report helper, scan helper, transport glue, and any fallback request dispatch that is duplicated in Swift.

### 4. Remove Node data-serving responsibilities

- [ ] Delete Node-only static file serving from the macOS app path.
  - Success means the UI is served by the new native path or by a separate explicit fallback, not by the legacy host.
- [ ] Delete Node-only report and history endpoints once Swift owns the equivalent contract.
  - Success means the UI still receives the same payloads without the Node host.

### 5. Remove legacy process ownership

- [ ] Remove Node-specific process lifecycle ownership from the macOS path.
  - Success means launcher, readiness, and restart flow are all native.
- [ ] Remove shell-backed helpers that only exist to support the old host path.
  - Success means the remaining runtime helpers are either native Swift or clearly isolated non-app tooling.

### 6. Remove the Node runtime entirely

- [ ] Delete the Node app host once the macOS app starts, scans, reports, syncs, and stops cleanly without it.
- [ ] Remove any remaining Node-only files and scripts that are no longer used by the macOS product path.
- [ ] Update packaging and documentation so the Swift-native app is the default and the old host is no longer mentioned as part of the shipping path.

## Verification Gates

- [x] `swift test` passes.
- [x] `node --check server.js` passes while Node remains in the tree.
- [ ] `./packaging/macos/bundle.sh` builds successfully from the Swift app path.
- [ ] App launch reaches ready state without Node as the primary host.
- [ ] A quick scan completes end-to-end.
- [ ] A complete scan completes end-to-end.
- [ ] Reports still generate and open correctly.
- [ ] Google Drive connect, disconnect, and status flows still work.
- [ ] Auto-scan enable/disable flows still work.
- [ ] The nightly eval loop stays green after Node removal.

## Exit Criteria

Treat the migration as complete only when all of the following are true:

- Swift is the only macOS app host.
- The UI transport is no longer dependent on Node.
- Scan orchestration and lifecycle emission come from Swift.
- Reports, history, auto-scan, and Google Drive still behave correctly.
- No legacy Node app-host code remains in the shipping macOS path.

## Suggested Order

1. Remove `server.js` from the macOS host path.
2. Remove the Socket.IO transport from the app path.
3. Delete scan orchestration fallback code.
4. Delete legacy helper glue and host-only data serving.
5. Remove remaining Node-only files, scripts, and references.
6. Verify the bundle and nightly eval loop after each slice.

## Notes

- Keep each removal slice small enough to verify quickly.
- Do not mark a legacy path as removed until the shipping app no longer depends on it.
- If a temporary compatibility bridge is still needed, call it out explicitly and keep it isolated.
