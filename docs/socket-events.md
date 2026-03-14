# Socket.IO Event Reference

All real-time communication between the NmapUI Flask server and the browser
uses Socket.IO. Events are plain JSON payloads sent over a single WebSocket
connection established on page load.

**Direction key:**
- `C → S` — client (browser) emits, server handles
- `S → C` — server emits, client handles

---

## Connection / Auth

| Event | Direction | When | Payload |
|---|---|---|---|
| `connect` | C → S | Browser connects or reconnects | _(none)_ |
| `disconnect` | C → S | Browser closes or navigates away | _(none)_ |
| `auth_error` | S → C | Socket handler rejected the request | `{ error: string }` |

---

## Network / Local IP Discovery

| Event | Direction | When | Payload |
|---|---|---|---|
| `get_local_ip` | C → S | Page load — request local network info | _(none)_ |
| `local_ip` | S → C | Response with network info | `{ ip, subnet_mask, cidr, public_ip, interface }` |
| `get_network_key` | C → S | Request full traceroute/hop data | _(none)_ |
| `network_key` | S → C | Traceroute result | `{ hops, exit_ip, public_ip, private_hops, public_hops, raw }` |
| `get_network_statistics` | C → S | Request hop summary counters | _(none)_ |
| `network_statistics` | S → C | Hop count summary | `{ total_hops, private_hops, public_hops, exit_ip }` |

---

## Customer Identification

| Event | Direction | When | Payload |
|---|---|---|---|
| `customer_identification_start` | S → C | Fingerprint matching begins | _(none)_ |
| `customer_info` | S → C | Matched customer (or unknown) | Full customer object `{ id, name, confidence, ... }` |
| `customer_identification_error` | S → C | Fingerprint error | `{ error: string }` |
| `get_customers` | C → S | Request full customer list | _(none)_ |
| `customers_list` | S → C | Full customer list response | `{ customers: Customer[] }` |
| `get_customer_info` | C → S | Request info for specific customer | `{ customer_id: string }` |
| `add_customer` | C → S | Create a new customer record | Customer object |
| `delete_customer` | C → S | Remove a customer record | `{ customer_id: string }` |
| `assign_customer` | C → S | Manually assign current network to customer | `{ customer_id: string }` |
| `customer_error` | S → C | Customer operation failed | `{ error: string }` |
| `get_customer_traceroutes` | C → S | Fetch traceroute history for customer | `{ customer_id: string }` |
| `customer_traceroutes` | S → C | Traceroute history response | `{ customer_id, traceroutes: Traceroute[] }` |

---

## Scan Lifecycle

### Quick Scan → ARP → Deep Scan

| Event | Direction | When | Payload |
|---|---|---|---|
| `start_scan` | C → S | User clicks Scan | `{ target: string }` |
| `quick_scan_start` | S → C | Quick ping sweep begins | `string` (status message) |
| `scan_feedback` | S → C | Progress message throughout entire scan | `string` |
| `scan_raw_output` | S → C | Raw nmap stdout line(s) for audit log | `{ target: string, output: string }` |
| `quick_scan_complete` | S → C | Ping sweep finished | _(none)_ |
| `scan_results` | S → C | Initial host list from quick scan | `Host[]` |
| `arp_scan_start` | S → C | ARP scan begins | _(none)_ |
| `arp_results` | S → C | MAC / vendor data by IP | `{ [ip]: { mac, vendor } }` |
| `arp_scan_complete` | S → C | ARP scan finished | _(none)_ |
| `deep_scan_start` | S → C | Deep scan phase begins | _(none)_ |
| `deep_scan_host_start` | S → C | Deep scan starting a specific host | `{ ip: string }` |
| `deep_scan_results` | S → C | Port/service data for one host | `Host[]` (single-element) |
| `cve_array` | S → C | CVEs found for one host | `{ target: string, cve_array: CVE[] }` |
| `service_info` | S → C | Extra service info line from nmap | `{ target: string, line: string }` |
| `deep_scan_host_complete` | S → C | Deep scan finished for one host | `{ ip: string }` |
| `deep_scan_complete` | S → C | All deep scans done | _(none)_ |
| `scan_error` | S → C | Any scan-phase error | `string` or `{ error: string }` |

### Resumable Scan State

| Event | Direction | When | Payload |
|---|---|---|---|
| `check_resumable_scan` | C → S | Page load — check for an in-progress scan | _(none)_ |
| `resumable_scan_check` | S → C | Result of resume check | `{ has_scan: bool, hosts?: Host[] }` |
| `resume_from_last_scan` | C → S | User requests resume | _(none)_ |
| `resume_scan_error` | S → C | Resume failed | `{ error: string }` |

---

## Report Generation

| Event | Direction | When | Payload |
|---|---|---|---|
| `generate_report` | C → S | User triggers report | `{ target, customer_name, auto_scan? }` |
| `scan_feedback` | S → C | Progress messages (shared with scan) | `string` |
| `scan_complete_summary` | S → C | Stats after report scan completes | `{ duration_formatted, hosts_up, total_ports, total_cves, target }` |
| `report_complete` | S → C | Report files ready | `{ status, path, scan_dir }` |
| `report_error` | S → C | Report generation failed | `{ error: string, timeout?: bool }` |
| `assign_report_to_customer` | C → S | Link a report directory to a customer | `{ scan_dir, customer_id }` |

---

## Job Status / Progress

| Event | Direction | When | Payload |
|---|---|---|---|
| `get_job_status` | C → S | Poll current job state | `{ job_type: 'scan' | 'report' }` |
| `job_status` | S → C | Current job state | `{ job_type, status, started_at, ... }` |
| `job_progress` | S → C | Structured progress update | `{ job_type, phase, message, progress: 0-100, details? }` |
| `cancel_job` | C → S | Request cancellation | `{ job_type: 'scan' | 'report' }` |
| `job_cancelled` | S → C | Cancellation acknowledged | `{ job_type, message }` |

---

## Scan History

| Event | Direction | When | Payload |
|---|---|---|---|
| `search_scan_history` | C → S | Query stored scan reports | `{ query?, customer_id?, limit? }` |
| `scan_history_results` | S → C | History query response | `{ results: ScanMeta[] }` |
| `get_history_counts` | C → S | Request archive counts per customer | _(none)_ |
| `history_counts` | S → C | Archive count response | `{ counts: { [customer_id]: number } }` |

---

## Auto-Scan

| Event | Direction | When | Payload |
|---|---|---|---|
| `update_auto_scan` | C → S | Save auto-scan schedule settings | `{ enabled, start_time, end_time }` |
| `auto_scan_status` | S → C | Confirmation of schedule save | `{ enabled, start_time, end_time, last_run }` |
| `auto_scan_error` | S → C | Auto-scan trigger failed | `{ error: string }` |
| `add_labeled_public_ip` | C → S | Tag a public IP with a label | `{ ip, label, customer_id }` |

---

## App Updates

| Event | Direction | When | Payload |
|---|---|---|---|
| `check_app_updates` | C → S | Check for newer version | _(none)_ |
| `app_update_available` | S → C | New version found | `{ version, description }` |
| `update_status` | S → C | Update progress message | `{ message: string }` |
| `update_error` | S → C | Update failed | `{ error: string }` |
| `perform_app_update` | C → S | Trigger update + restart | _(none)_ |
| `show_auto_update_banner` | S → C | Show countdown update banner | `{ version, description }` |
| `hide_auto_update_banner` | S → C | Dismiss banner | _(none)_ |
| `start_auto_update_countdown` | S → C | Start countdown timer | `{ seconds: number }` |
| `cancel_auto_update` | C → S | User dismissed update banner | _(none)_ |
| `idle_state_changed` | S → C | Server idle/busy state changed | `{ idle: bool }` |

---

## Versions

| Event | Direction | When | Payload |
|---|---|---|---|
| `get_versions` | C → S | Request tool version strings | _(none)_ |
| `versions` | S → C | Tool versions response | `{ nmap, vulners, arp_scan, app }` |

---

## Type Definitions

```typescript
interface Host {
  ip: string
  hostname?: string
  status?: string
  mac?: string
  vendor?: string
  open_ports?: string          // "80/http, 443/https"
  version?: string
  cves?: string | CVE[]
  ports?: Port[]
}

interface Port {
  port: string
  state: string
  service: string
}

interface CVE {
  id: string        // "CVE-2021-44228"
  score: string     // "9.8"
  url: string
}

interface ScanMeta {
  customer_name: string
  customer_id: string
  target: string
  timestamp: string
  date: string
  files: Record<string, string>
}
```
