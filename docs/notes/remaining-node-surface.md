# Remaining Node Surface

This note is an exhaustive inventory of what `server.js` still owns versus what the Swift shell already owns.

It is intentionally descriptive, not an authorization to keep Node around forever.

## Already Swift-owned

- Process launch and restart control
  - `packaging/macos/Sources/NmapUIApp/RuntimeLifecycleController.swift`
  - `packaging/macos/Sources/NmapUIApp/StartupCoordinator.swift`
  - `packaging/macos/Sources/NmapUIApp/RuntimeBridge.swift`
- Scan execution
  - `packaging/macos/Sources/NmapUIApp/ScanCoordinator.swift`
- Runtime metadata persistence
  - `packaging/macos/Sources/NmapUIApp/RuntimeMetadataStore.swift`
- Runtime state snapshotting
  - `packaging/macos/Sources/NmapUIApp/RuntimeScanState.swift`
  - `packaging/macos/Sources/NmapUIApp/AppSessionState.swift`
- Typed request contract and first request dispatcher slice
  - `packaging/macos/Sources/RuntimeContracts/RuntimeRequestContract.swift`
  - `packaging/macos/Sources/NmapUIApp/RuntimeRequestDispatcher.swift`
- Report naming, report metadata, and XML parsing helpers
  - `packaging/macos/Sources/NmapUIApp/RuntimeReportNaming.swift`
  - `packaging/macos/Sources/NmapUIApp/RuntimeReportMetadata.swift`
  - `packaging/macos/Sources/NmapUIApp/RuntimeNmapXMLSummary.swift`

## Still Node-owned

### Transport and socket routing

- Socket.IO connection lifecycle
- Initial data emission
- Scan lifecycle events
- Scan stop event
- Auto-scan settings events
- History request/response routing
- Customer profile request/response routing
- Google Drive request/response routing
- Reports request/response routing
- Request parsing for typed scan-start payloads is now shared in Swift, but the live socket transport still sits in Node.

### Scan orchestration surface

- `sync_state`
- `scan_started`
- `phase_complete`
- `phase_stats`
- `scan_complete`
- `start_quick_scan`
- `start_complete_scan`
- `start_dragnet_scan`

### Settings surface

- `enable_auto_scan`
- `disable_auto_scan`
- `set_customer_profile_prefix`

### Data surface

- `get_history`
- `get_customer_profile`
- `get_reports`
- `get_google_drive_status`
- `save_google_drive_credentials`
- `connect_google_drive`
- `disconnect_google_drive`
- `save_google_drive_settings`

### Helper bridge surface

- `runRuntimeReportHelper(...)`
- `runGoogleDriveHelper(...)`
- `buildReportsSnapshot()`
- `buildRuntimeReportHistoryEntry(...)`
- `generateReportFromXml(...)`
- `getRuntimeBootstrapSnapshot()`

## What this means

- Swift already owns the runtime launch and scan execution core.
- Node still owns the browser-facing event router and most UI contract emission.
- Swift now owns a typed request contract and a dispatcher slice for bootstrap, settings, history, reports, and profile data.
- The next true migration step is moving the live transport/event router itself into Swift, not just moving more helper logic.

## Migration order

1. Move the Socket.IO event boundary.
2. Move scan state and lifecycle emission.
3. Move reports and history emission.
4. Move auto-scan and customer profile state.
5. Move Google Drive control flow.
6. Remove Node only after the UI can run against the Swift-owned contract.
