# NmapUI Nightly Product Evaluation Loop

This loop is the best fit from the loop library for NmapUI because it tests the
real product surfaces the repo already automates: scan execution, report
generation, Socket.IO replay, and update flows.

## Loop Shape

Trigger the loop nightly or before a release candidate, then run the same small
scenario set every time:

1. Quick scan against a safe target.
2. Deep scan with CVE output enabled.
3. HTML and PDF report generation.
4. Auto-scan schedule validation.
5. Auto-monitor rule validation.
6. Job reconnect and replay handling.
7. Update banner and idle-state flow.

## What To Record

- Scenario results in order.
- The target or config used.
- Generated artifact paths.
- Any blocker or warning.
- The git revision the run came from.

## Stop Condition

Stop only when the same scenario set passes under the same conditions and the
current runtime contract still matches the expected Socket.IO and report
behavior.

## Runner

Use [`scripts/nightly_product_eval.sh`](/Users/seandolbec/Projects/NmapUI/scripts/nightly_product_eval.sh)
for dry runs, recording, or the socket smoke verification pass.

For macOS scheduling, install
[`packaging/macos/com.nmapui.nightly-product-eval.plist`](/Users/seandolbec/Projects/NmapUI/packaging/macos/com.nmapui.nightly-product-eval.plist)
into `~/Library/LaunchAgents/` and load it with `launchctl`.

For GitHub Actions, the workflow supports both nightly scheduled runs and
manual dispatches with either `run` or `dry-run` mode.

## Why This Loop Matters

- It complements the existing PR loop instead of duplicating it.
- It turns the app's existing automation surface into a repeatable validation
  loop.
- It gives a consistent artifact trail for regressions and release confidence.
