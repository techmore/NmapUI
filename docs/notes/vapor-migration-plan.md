# Vapor Migration Plan

This is the follow-on plan for the day after the Swift migration is complete.

It is intentionally separate from the current Swift migration work. Do not use this plan to justify delaying the remaining Swift transport replacement work.

## Purpose

Move backend orchestration from a local Node runtime into a Swift server built with Vapor, once the macOS app is already stable in Swift and the Node transport shim is no longer carrying the product runtime.

The goal of this phase is not to “make the app more Swift” in the abstract. The goal is to create a maintainable backend service boundary that can own:

- asset tracking
- scan history
- scan scheduling
- report persistence
- sync state
- API surface for future clients

## When this plan becomes relevant

Only start this migration after all of the following are true:

- The current Swift migration is complete and verified.
- The macOS app no longer depends on `server.js` for live transport.
- The product can launch, scan, stop, report, and sync without Node acting as the runtime control plane.
- The current loopback or equivalent client contract has a stable replacement boundary in Swift.

## Target architecture

### Client side

- Keep the macOS app as the local shell and launcher.
- Keep the app responsible for startup, readiness, and local user interaction.
- Keep the client-facing runtime contract explicit and typed.

### Vapor backend

- Use Vapor as the backend service for runtime orchestration and data APIs.
- Expose structured endpoints for:
  - scan lifecycle control
  - asset inventory
  - report lookup and download
  - historical scan data
  - customer profile or tenancy metadata
  - sync state and health checks
- Keep the backend implementation stateless where possible, with durable storage owning the source of truth.

### Shared contracts

- Define the request and event envelopes as shared Swift models.
- Keep the wire contract versioned and backward compatible.
- Treat the macOS client and Vapor backend as separate executables with a shared contract layer, not as two copies of the same runtime logic.

## Migration phases

### Phase 1: contract extraction

- Move the remaining runtime message shapes into a shared Swift module.
- Separate transport envelopes from runtime behavior.
- Define versioning for request and event payloads.
- Add compatibility fallbacks for older client payloads only where needed.

### Phase 2: backend skeleton

- Create a Vapor service target.
- Add health and readiness endpoints first.
- Add a minimal identity endpoint that replaces the current runtime handshake.
- Wire local development so the macOS app can point at Vapor without changing the client UI contract.

### Phase 3: data ownership

- Move persisted metadata into a durable backend store.
- Add repositories or service layers for:
  - history
  - reports
  - scan metadata
  - asset records
  - customer profile data
- Keep file formats and download paths stable during the transition.

### Phase 4: orchestration endpoints

- Add scan start, stop, and status endpoints.
- Add scheduling controls for auto-scan.
- Add Google Drive sync controls if they remain backend-owned.
- Emit event updates through the Vapor service instead of through a local Socket.IO runtime.

### Phase 5: client cutover

- Point the macOS shell at the Vapor backend.
- Keep the old Node path behind a feature flag or development fallback until parity is proven.
- Verify the app can boot, scan, and show history against the Vapor backend only.

### Phase 6: Node removal

- Remove the Node runtime from the main path.
- Delete Node-only helper scripts once the Vapor replacement is proven.
- Archive any remaining Node-specific implementation notes.

## Suggested implementation order

1. Define the shared contract module.
2. Stand up a Vapor health server.
3. Move identity and readiness checks.
4. Move history and report lookup.
5. Move scan lifecycle endpoints.
6. Move scheduling and sync controls.
7. Cut the macOS client over.
8. Remove Node from the production path.

## Verification gates

- Vapor service starts locally and passes a readiness check.
- The macOS client can connect to the Vapor backend without changing the UI contract.
- Existing scan and report workflows still complete end to end.
- History and report data remain stable after the cutover.
- The nightly evaluation loop can run against the new backend.
- Node can be disabled without breaking the primary user path.

## Risks and constraints

- Do not start Vapor work before the Swift migration is actually done.
- Do not duplicate backend logic between Node and Vapor for long periods.
- Do not change the user-visible contract unless the new one is versioned and verified.
- Keep the migration incremental so the macOS app can remain usable during the transition.

## Exit criteria

The Vapor migration is complete when:

- the macOS app no longer needs Node as a runtime dependency,
- the Vapor backend owns the remaining orchestration and data services,
- and the full product flow is verified against the Swift/Vapor stack.

