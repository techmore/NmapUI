# Report Stylesheet Strategy

## Current Direction

NmapUI uses a shared visual language across HTML and PDF reports, with an intentional split between:

- `nmap-modern.xsl` for the interactive browser report
- `nmap-pdf-olive-legacy.xsl` for the print-first PDF HTML

This is not a full fork in design language. It is a print-safe variant of the same report structure.

## What Should Stay Shared

Both report modes should preserve the same core report landmarks and visual identity:

- olive color system
- Instrument Serif and Inter typography
- primary report sections such as:
  - `#scannedhosts`
  - `#openservices`
  - `#onlinehosts`
- the same host, service, and vulnerability content ordering where practical

## Intentional Differences

The browser report may keep interactive assets that do not belong in exported PDF output:

- DataTables CSS and JS
- jQuery
- client-side sorting/export affordances

The PDF stylesheet should remain print-first:

- no external interactive JS dependencies
- no DataTables runtime
- predictable print layout and page breaks
- Playwright PDF rendering under `print` media

## Regression Expectations

Changes to either stylesheet should preserve:

- shared landmark sections in rendered HTML
- matching representative host/service content in both outputs
- absence of DataTables and jQuery assets in the PDF-rendered HTML

Representative regression coverage lives in:

- `tests/test_reporting_modules.py`
- `tests/test_runtime_contract.py`
