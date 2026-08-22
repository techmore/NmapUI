# VPN Helper Design

## Goal

VPN Helper is a reliability mode for remote, high-latency, lossy, or very large network scans. It is not intended to replace the normal local-network scan path. Normal scans keep the faster single-command Phase 2 workflow.

## When To Use It

Use VPN Helper when:

- scanning across a VPN tunnel
- Phase 2 repeatedly stalls or crashes
- discovery finds hundreds of hosts
- the scope includes large routed ranges
- the network path is high latency or packet loss is likely

For local LANs and small scopes, start with the normal Complete + PDF scan.

## Phase Model

### Normal Complete + PDF

```text
Phase 1: discovery
Phase 2: combined service/version/OS/vulners scan
Phase 3: gowitness screenshots
Report generation
```

### VPN Helper Complete + PDF

```text
Phase 1: discovery using the normal stable discovery path
Phase 2.1: batch the successful Phase 1 live IPs, then run service/version scan
Phase 2.2: batch the same successful Phase 1 live IPs, then run vulners scan
Phase 3: gowitness screenshots
Report generation
```

VPN Helper makes the existing fallback split the default path after Phase 1 completes. It does not batch the original requested ranges. It batches only the successful IPs discovered in Phase 1. This prevents one large Nmap/NSE command from blocking the whole report while preserving the stable VPN discovery behavior.

## Batch Defaults

Default batch size: `50` hosts.

Reasoning:

- `25` is safer but can be too slow on large school networks.
- `100` can still create long stalls over VPN.
- `50` gives useful progress visibility and keeps failures isolated.

Batch size can become configurable later.

## OS Detection

VPN Helper disables OS detection by default because `-O` can be slow and unreliable across VPN links.

The UI exposes a nested toggle:

```text
Force OS Detection (-O)
```

When enabled, Phase 2.1 includes `-O`.

## Commands

Phase 2.1 default:

```bash
sudo -n nmap -sS -sV -Pn -T2 --open --max-parallelism 15 --max-retries 2 -oX phase2_vpn_service_batch_001.xml -iL targets_vpn_batch_001.tmp
```

Phase 2.1 with Force OS Detection:

```bash
sudo -n nmap -sS -sV -O -Pn -T2 --open --max-parallelism 15 --max-retries 2 -oX phase2_vpn_service_batch_001.xml -iL targets_vpn_batch_001.tmp
```

Phase 2.2:

```bash
sudo -n nmap -sV --script vulners --script-args mincvss=0,threads=5 -oX phase2_vpn_vulners_batch_001.xml -iL targets_vpn_batch_001.tmp
```

## Failure Behavior

VPN Helper should not be all-or-nothing.

- A failed batch is logged.
- Later batches continue.
- Successful XML files are merged into a final report input.
- The final report is generated when at least one batch produces complete XML.
- The scan result is marked partial when any batch pass fails.

## Large Scope Behavior

Some Meraki environments advertise broad routed ranges, including `/8`. VPN Helper does not block those scopes when they are required and approved, but future guardrails should warn users before starting very large scans.

Recommended future warnings:

- warn above `4,096` addresses
- require explicit confirmation above `16,384` addresses
- special warning for `/16` or larger
- strong warning for `/8`

## Report Notes To Add Later

Future reports should include VPN Helper metadata:

- VPN Helper enabled
- batch size
- Force OS Detection enabled/disabled
- number of successful batch passes
- number of failed batch passes
- partial coverage warning when applicable

## Current Limitations

- Batch size is fixed at `50`.
- Merged XML is generated from successful batch XML files.
- Failed batch details are logged but not yet surfaced as a dedicated report section.
- Per-subnet report organization is not implemented yet.
