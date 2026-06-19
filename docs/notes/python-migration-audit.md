# Python Migration Audit

This is the first pass at separating Python that is useful as deployment glue from Python that is part of the product surface.

## Likely glue

- `scripts/nightly_product_eval.sh`
  - Mostly orchestration around checks, logs, and automated validation.
  - Its timestamp and JSON report generation are now handled without Python.
  - The socket smoke path now uses a native Node helper instead of Python.

## Still required for parity

- `google_drive_bridge.js` now dispatches directly to the native helper.
  - The legacy `google_drive.py` helper has been removed.
  - Any remaining Python usage should be treated as legacy or test-only until proven otherwise.

## Likely product behavior

- Any Python that participates directly in scan/report generation or user-visible export behavior should be treated as product logic, not deployment glue.
- Those paths should be migrated only after a Swift replacement proves parity on the same inputs and outputs.

## Migration order

1. Keep the web frontend and backend behavior unchanged.
2. Replace packaging and launch glue first.
3. Move user-visible helpers next, starting with Google Drive sync plumbing and continue until any remaining native-helper rough edges are closed.
4. Leave core scan/report semantics alone until the native replacements match them closely.

## Current risk

- The deployment story feels brittle when Python is used for startup or packaging glue.
- That makes the shell and launcher the best first targets for SwiftUI migration.
