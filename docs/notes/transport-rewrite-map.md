# Transport Rewrite Map

This note turns the remaining Node-owned Socket.IO surface into a concrete Swift migration sequence.

It is a migration aid, not a substitute for the actual transport rewrite.

## Current state

- Swift already owns the process launcher, runtime startup checks, scan execution, and shared runtime contracts.
- Node still owns the live Socket.IO connection, event dispatch, and browser-facing UI contract.
- The shared Swift event router now provides a typed place to emit future transport messages.
- Swift also now owns a typed client request contract and a first request-dispatcher slice for bootstrap, data, settings, and scan-start parsing.
- Swift now also owns the typed `scan_stopped` request response path.

## Event families to replace

### Connection and bootstrap

- `get_initial_data`
- `initial_data`
- `sync_state`

Target Swift owners:
- `RuntimeEventRouter`
- `RuntimeInitialDataEnvelope`
- `RuntimeScanLifecycleEnvelope`

### Scan lifecycle

- `start_quick_scan`
- `start_complete_scan`
- `start_dragnet_scan`
- `scan_started`
- `phase_complete`
- `phase_stats`
- `scan_complete`
- `scan_stopped`

Target Swift owners:
- `ScanCoordinator`
- `RuntimeEventRouter`
- `RuntimePhaseCompleteEnvelope`
- `RuntimePhaseStatsEnvelope`
- `RuntimeScanLifecycleEnvelope`

### Discovery and traceroute

- `discovery_update`
- `traceroute_hop`

Target Swift owners:
- `RuntimeEventRouter`
- `RuntimeDiscoveryUpdateEnvelope`
- `RuntimeTracerouteHopEnvelope`

### Reports and history

- `get_history`
- `history_data`
- `get_reports`
- `reports_data`
- `report_ready`
- `reports_refresh`
- `log_entry`

Target Swift owners:
- `RuntimeMetadataStore`
- `RuntimeReportHelper`
- `RuntimeEventRouter`
- `RuntimeReportReadyEnvelope`

### Customer profile and auto-scan

- `get_customer_profile`
- `customer_profile`
- `set_customer_profile_prefix`
- `enable_auto_scan`
- `disable_auto_scan`
- `auto_scan_config`

Target Swift owners:
- `RuntimeCustomerProfile`
- `RuntimeEventRouter`
- `RuntimeInitialDataEnvelope`

### Google Drive

- `get_google_drive_status`
- `google_drive_status`
- `google_drive_auth_url`
- `save_google_drive_credentials`
- `connect_google_drive`
- `disconnect_google_drive`
- `save_google_drive_settings`

Target Swift owners:
- `RuntimeGoogleDriveStatusEnvelope`
- `RuntimeEventRouter`
- `RuntimeReportMetadata`

## Rewrite sequence

1. Replace bootstrap/state emissions with Swift-owned event construction.
2. Move scan lifecycle emission out of Node and into Swift.
3. Move report/history emission into Swift.
4. Move customer profile and auto-scan emissions into Swift.
5. Move Google Drive status/auth flows into Swift.
6. Remove the Node event router only after the Swift transport path can serve the same UI contract.

## Verification gates

- `swift test`
- `node --check server.js`
- A full scan can still start and complete during the transition.
- The existing web UI still receives the same event payload shapes.
- The loopback readiness contract stays stable while the transport boundary moves.
