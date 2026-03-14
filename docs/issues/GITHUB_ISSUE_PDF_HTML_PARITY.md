# PDF Reports Should Match HTML Reports More Closely

## Summary

The HTML scan report has a much stronger visual presentation than the generated PDF. We should bring PDF output into visual parity with the HTML report so exported reports look intentional rather than like a degraded fallback.

## Investigation Findings

1. The report workflow currently allows stylesheet drift between the HTML and PDF render paths.
2. The saved-scan PDF flow was regenerating both `scan_web.html` and `scan_pdf.html` with the PDF stylesheet instead of preserving the primary HTML styling.
3. `convert_html_to_pdf()` did not wait for hosted fonts and CDN assets to settle before rendering with Playwright, which can produce partially styled output.
4. The `wkhtmltopdf` fallback forced `--print-media-type`, which biases rendering away from the on-screen presentation we are trying to preserve.
5. There is a legacy PDF stylesheet (`nmap-pdf-olive-legacy.xsl`) that has drifted from the primary modern stylesheet, making PDF appearance harder to keep aligned with the HTML version.

## Desired Outcome

PDF exports should preserve the same visual language as the HTML report:

- same typography hierarchy
- same olive theme and card treatment
- same table presentation and spacing where practical
- reliable asset loading before capture
- predictable US Letter output

## Proposed Work

1. Route web HTML and PDF HTML through explicit stylesheet inputs instead of a shared ambiguous parameter.
2. Default PDF generation to the same modern stylesheet as the HTML report while we evaluate whether a dedicated print override is still needed.
3. Improve Playwright PDF capture by waiting for network idle, emulating screen media, and using consistent page sizing.
4. Improve `wkhtmltopdf` fallback settings so it favors the screen presentation instead of print-media degradation.
5. Decide whether to retire or rebuild `nmap-pdf-olive-legacy.xsl` as a thin print-override layer instead of a forked full stylesheet.
6. Add regression coverage for stylesheet selection in report generation.

## Acceptance Criteria

- A newly generated PDF is visually much closer to the corresponding HTML report.
- The saved-scan PDF regeneration path uses the intended web/PDF stylesheet split.
- Playwright-based PDF generation waits for the page to finish loading before capture.
- Fallback PDF generation no longer forces print media.
- Automated tests cover the stylesheet routing change.

## Notes

Initial implementation work has already started in this branch to address the workflow wiring and renderer behavior.
