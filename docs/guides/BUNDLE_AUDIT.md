# Bundle Audit

## Current Packaging Choice

NmapUI keeps Vulners-based CVE detection bundled, but only ships the runtime files required by the supported workflow:

- `vulners.nse`
- `http-vulners-regex.nse`
- `http-vulners-regex.json`
- `http-vulners-paths.txt`
- `LICENSE`

The packaged app does not need to ship:

- `vulners_enterprise.nse`
- repository screenshots or example images
- the upstream `nmap-vulners` README

Those assets are useful for upstream development and documentation, but they are not needed for scan execution or report generation.

## Why This Split

- Keeps the supported CVE/reporting path intact
- Reduces packaged asset sprawl
- Avoids shipping enterprise-only or documentation-only files into the local app bundle

## UI Choice

Tool versions remain available, but they no longer live in the main header hover surface.

- `app-version` remains visible in the header
- Nmap, Vulners, and ARP-Scan versions now live in the Settings tab runtime summary

This keeps the dashboard focused on scanning state while preserving diagnostics in a lower-noise location.
