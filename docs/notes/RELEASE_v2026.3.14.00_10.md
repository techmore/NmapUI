# Release Notes Draft: v2026.3.14.00_10

## Summary

This release candidate focuses on three areas:

- multi-tab runtime synchronization
- SQLite-backed history, reports, logs, and runtime replay
- reporting, customer, and packaged-app workflow improvements

## Major Changes

### Multi-Tab Runtime Sync

- improved scan/report runtime fanout across multiple open tabs
- added replay support for active jobs, job events, and persisted runtime state
- tightened scan/report pulse precedence so the wrong action button is less likely to pulse on secondary tabs
- added regression coverage for:
  - tabs already open before a scan/report starts
  - tabs opened after a scan/report is already active
  - handler-level existing-tab fanout behavior

### SQLite Runtime Store

- runtime state is now persisted in SQLite for:
  - snapshots
  - jobs
  - replay events
  - runtime logs
  - report artifacts
  - customer scan history
- added runtime database export
- added build-time migration path
- added schema versioning and startup migration handling
- added retention and compaction maintenance actions

### Reports, History, and Customers

- Reports tab now uses runtime-backed artifact APIs
- History defaults to current network/customer context
- added compare-any-two history flow
- added customer filter tags for reports
- added dedicated Customers tab
- normalized saved report/customer naming away from stale auto-detect labels

### Packaging and Runtime Operations

- `build.sh` installs the app into `/Applications` or `~/Applications`
- bundle version now comes from `VERSION`
- Playwright report browser assets are provisioned in install/build flows
- runtime database export and maintenance actions are available from Settings

### Security and Secret Handling

- Google Drive tokens are encrypted at rest
- remote sync API keys are encrypted at rest

## Verification

Automated verification on the release candidate branch:

- `./.venv/bin/python -m pytest -q`
- result: `284 passed, 8 skipped`

## Recommended Manual Checks Before Publish

- packaged app launches from installed Applications location
- Quick Scan from tab 1 updates tab 2 if both tabs are already open
- opening tab 2 after a scan already starts keeps the scan button pulsing
- Complete + PDF from tab 1 updates tab 2 correctly
- Reports, History, and Customers tabs show saved data correctly
- runtime DB export works from Settings

## Known Caution

- multi-tab behavior in the packaged app has had several regressions recently
- automated coverage is much stronger now, but one final packaged manual validation pass is still recommended before publishing this as a stable release

## Suggested Release Title

- `v2026.3.14.00_10 - Multitab Sync and Runtime History`
