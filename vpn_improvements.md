# VPN Scan Improvements

## Context

William Penn Charter scan testing over Meraki VPN exposed a practical problem: Meraki can advertise very broad VLAN interfaces, including `10.0.0.4/8`. Nmap treats that as the entire `10.0.0.0/8` space, which is roughly 16.7 million addresses. That is not a practical scope for VPN-based discovery or Phase 2 service/vulnerability scanning.

The current VPN helper is useful, but large VPN scans need stronger guardrails, better progress visibility, and safer batching.

## Immediate Scan Guidance

Avoid scanning `10.0.0.4/8` directly unless the client explicitly confirms that the entire `10.0.0.0/8` range is in scope and reachable.

Prefer scanning the specific VLAN ranges from the Meraki dashboard:

```text
172.17.1.1/22,
172.18.1.1/24,
172.19.1.1/24,
172.20.1.1/24,
172.21.1.1/23,
172.22.1.1/24,
172.23.1.1/24,
172.25.1.1/24,
172.25.0.1/24,
192.168.1.1/24,
192.168.99.1/24,
192.168.100.1/24,
192.168.200.1/24,
192.168.222.1/24
```

Recommended grouping:

```text
# Small validation first
192.168.100.1/24

# School service VLANs
192.168.1.1/24,
192.168.99.1/24,
192.168.200.1/24,
192.168.222.1/24

# 172 ranges in chunks
172.18.1.1/24,
172.19.1.1/24,
172.20.1.1/24,
172.22.1.1/24

172.17.1.1/22

172.21.1.1/23

172.23.1.1/24,
172.25.0.1/24,
172.25.1.1/24
```

## Product Improvements

### 1. Scope Size Guardrails

Add target parsing before Phase 1 starts.

Suggested behavior:

- Show total estimated IPv4 address count before scan.
- Warn above `4,096` addresses.
- Require explicit confirmation above `16,384` addresses.
- Special-confirm `/16` or larger.
- Hard warning for `/8`, with text explaining that it is about 16.7 million addresses.
- Suggest splitting broad targets into VLAN-sized ranges.

### 2. VPN Helper Should Batch Phase 2

VPN helper should do more than adjust Nmap timing.

Suggested behavior:

- Split Phase 2 into batches of 25 to 50 hosts.
- Log `Batch X/Y` progress.
- Generate per-batch XML.
- Merge or summarize batch results into the report history.
- Continue after a failed batch and record the failure.
- Avoid one huge Nmap command against hundreds or thousands of hosts.

### 3. Better Long-Running Scan Logging

Large VPN scans can appear hung even when Nmap is waiting on timeouts, retries, filtered hosts, or NSE scripts.

Suggested logging:

- Last Nmap output timestamp.
- Current phase runtime.
- Current target count.
- Current batch and batch size.
- No-output watchdog message every 5 to 10 minutes.
- Nmap process PID.
- Most recent stderr line.
- Clear status when XML has not changed recently.

Example log messages:

```text
Phase 2 VPN helper batch 4/18 started. Hosts 151-200.
No Nmap output for 8m 12s. Process is still running, PID 12345.
Batch 4/18 finished with incomplete XML. Recording failure and continuing.
```

### 4. Safer Phase 2 Defaults Over VPN

VPN helper Phase 2 defaults should prioritize reliability over speed.

Possible defaults:

```text
-sS -sV -O -Pn
-T2
--open
--script vulners
--script-args mincvss=0,threads=5
--max-parallelism 15
--max-retries 2
```

Potential additions:

- Script timeout limits if supported.
- Host timeout for very slow hosts.
- Automatic fallback to service-only scan when NSE crashes.
- Optional skip of OS detection over VPN if it causes instability.

### 5. Per-Subnet Scan Mode

Add a mode that treats comma-separated targets as independent subnet jobs instead of one combined Nmap run.

Benefits:

- Easier progress reporting.
- Easier failure isolation.
- Better report history.
- Cleaner compliance evidence by VLAN/subnet.

Possible report organization:

```text
reports_archive/<customer>/<scan-date>/
  172.18.1.0_24/
  172.19.1.0_24/
  192.168.100.0_24/
```

### 6. Meraki-Aware Notes

Meraki VLAN interfaces may show subnet notation that is valid for routing but unsafe for scanner scope. A VLAN interface like `10.0.0.4/8` should trigger a clear warning.

Suggested warning:

```text
10.0.0.4/8 covers approximately 16.7 million IPv4 addresses. This is usually not appropriate for VPN scanning. Confirm exact routed subnets from Meraki before continuing.
```

## Open Questions

- Should large scans be blocked by default or just strongly confirmed?
- Should VPN helper automatically force per-subnet scans?
- What batch size is best for Meraki VPN: 25, 50, or configurable?
- Should Phase 2 skip OS detection by default over VPN?
- Should XML history be stored per batch or only after merged report generation?
- Should the app maintain a client-approved scope list separate from the scan target field?
