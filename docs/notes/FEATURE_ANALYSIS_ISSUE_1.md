# Feature Analysis: Resume Asset Display from Previous Scan (Issue #1)

## Executive Summary

**Status:** ✅ FEASIBLE - XML files contain complete asset data needed for resume functionality

**Key Finding:** Nmap XML scan files contain ALL the data currently displayed in the asset table, making it possible to resume asset display without re-running scans.

---

## XML Data Availability Analysis

### What Data We Need (Current Asset Table Display)

Based on the current UI, the asset discovery table displays:
1. **IP Address** - Host identifier
2. **Hostname** - DNS/PTR name
3. **MAC Address** - Hardware address
4. **Vendor** - MAC vendor lookup
5. **Open Ports** - List of open ports and services
6. **Status** - Host up/down state

### What's Available in XML Files

Examined sample XML: `/data/scans/Unknown_Network/2026-01-08/scan_190339_192.168.222.024/scan.xml`

#### ✅ Complete Data Available in XML

Each `<host>` element in the XML contains:

```xml
<host starttime="1767917033" endtime="1767917267">
  <!-- Status: up/down -->
  <status state="up" reason="arp-response" reason_ttl="0"/>

  <!-- IP Address -->
  <address addr="192.168.222.1" addrtype="ipv4"/>

  <!-- MAC Address + Vendor -->
  <address addr="1E:6A:1B:4B:6F:50" addrtype="mac"/>
  <!-- OR with vendor when known -->
  <address addr="54:2A:1B:86:C5:C1" addrtype="mac" vendor="Sonos"/>

  <!-- Hostname (when available) -->
  <hostnames>
    <hostname name="unifi.localdomain" type="PTR"/>
  </hostnames>

  <!-- Open Ports and Services -->
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack" reason_ttl="64"/>
      <service name="http" product="nginx" method="probed" conf="10">
        <cpe>cpe:/a:igor_sysoev:nginx</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack" reason_ttl="64"/>
      <service name="http" product="nginx" tunnel="ssl" method="probed" conf="10">
        <cpe>cpe:/a:igor_sysoev:nginx</cpe>
      </service>
    </port>
    <!-- ... more ports ... -->
  </ports>

  <!-- BONUS: OS Detection -->
  <os>
    <osmatch name="Linux 3.2 - 4.14" accuracy="96" line="68432">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="3.X" accuracy="96">
        <cpe>cpe:/o:linux:linux_kernel:3</cpe>
      </osclass>
    </osmatch>
  </os>
</host>
```

#### Additional Metadata Available

The XML also contains:
- **Scan timestamp**: `starttime` and `endtime` (Unix timestamps)
- **Scan command**: Full nmap command in header comment
- **Scan duration**: Calculable from start/end times
- **Total hosts scanned**: Count of `<host>` elements
- **Vulnerability data**: When vulners script runs
- **OS detection**: Operating system fingerprints
- **Service versions**: Detailed service information

---

## Implementation Plan

### Phase 1: XML Parser for Asset Resumption

#### 1.1 Create XML Parsing Function (app.py)

```python
def parse_scan_xml_for_assets(xml_path):
    """
    Parse nmap XML file and extract asset data in the same format
    as the current scan results.

    Returns:
        list: Asset data in format matching current scan output:
        [
            {
                "ip": "192.168.222.1",
                "hostname": "unifi.localdomain",
                "mac": "1E:6A:1B:4B:6F:50",
                "vendor": "",
                "ports": "80 (http), 443 (https), 8080 (http-proxy)",
                "status": "up"
            },
            ...
        ]
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        assets = []

        for host in root.findall('host'):
            # Skip hosts that are down
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue

            asset = {
                "ip": "",
                "hostname": "",
                "mac": "",
                "vendor": "",
                "ports": "",
                "status": "up"
            }

            # Extract IP address
            for addr in host.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    asset["ip"] = addr.get('addr')
                elif addr.get('addrtype') == 'mac':
                    asset["mac"] = addr.get('addr')
                    asset["vendor"] = addr.get('vendor', '')

            # Extract hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname = hostnames.find('hostname')
                if hostname is not None:
                    asset["hostname"] = hostname.get('name', '')

            # Extract open ports
            ports_elem = host.find('ports')
            if ports_elem is not None:
                open_ports = []
                for port in ports_elem.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = port.get('portid')
                        service = port.find('service')
                        service_name = service.get('name', '') if service is not None else ''
                        open_ports.append(f"{port_id} ({service_name})" if service_name else port_id)

                asset["ports"] = ", ".join(open_ports)

            assets.append(asset)

        return assets

    except Exception as e:
        logger.error(f"Failed to parse XML for asset resumption: {e}")
        return []
```

#### 1.2 Get Most Recent Scan for Customer

```python
def get_most_recent_scan_xml(customer_id, max_days=7):
    """
    Find the most recent scan XML file for a customer within max_days.

    Returns:
        tuple: (xml_path, scan_metadata) or (None, None) if not found
    """
    from datetime import datetime, timedelta

    # Find customer by ID
    customer = None
    for c in customer_fingerprinter.customers:
        if c.get('id') == customer_id:
            customer = c
            break

    if not customer:
        return None, None

    customer_name = customer.get('name', 'Unknown')
    customer_scans_dir = SCANS_DIR / customer_name

    if not customer_scans_dir.exists():
        return None, None

    # Find all scan directories with metadata.json
    cutoff_date = datetime.now() - timedelta(days=max_days)
    recent_scans = []

    for date_dir in customer_scans_dir.iterdir():
        if not date_dir.is_dir():
            continue

        for scan_dir in date_dir.iterdir():
            if not scan_dir.is_dir():
                continue

            metadata_file = scan_dir / 'metadata.json'
            xml_file = scan_dir / 'scan.xml'

            if not (metadata_file.exists() and xml_file.exists()):
                continue

            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)

                scan_time = datetime.fromisoformat(metadata.get('timestamp', ''))

                if scan_time >= cutoff_date:
                    recent_scans.append({
                        'xml_path': xml_file,
                        'metadata': metadata,
                        'scan_time': scan_time
                    })
            except:
                continue

    if not recent_scans:
        return None, None

    # Sort by scan time, most recent first
    recent_scans.sort(key=lambda x: x['scan_time'], reverse=True)
    most_recent = recent_scans[0]

    return most_recent['xml_path'], most_recent['metadata']
```

### Phase 2: Socket Events for Asset Resumption

#### 2.1 New Socket Event: Check for Resumable Scan

```python
@socketio.on('check_resumable_scan')
def check_resumable_scan_event(data):
    """
    Check if there's a recent scan available for resumption.
    Called when a customer is identified.
    """
    customer_id = data.get('customer_id')
    max_days = data.get('max_days', 7)

    if not customer_id or customer_id == 'unknown':
        emit('resumable_scan_check', {'available': False})
        return

    xml_path, metadata = get_most_recent_scan_xml(customer_id, max_days)

    if xml_path and metadata:
        emit('resumable_scan_check', {
            'available': True,
            'scan_date': metadata.get('timestamp'),
            'target': metadata.get('target'),
            'duration': metadata.get('duration', 'unknown'),
            'total_hosts': metadata.get('total_hosts', 0)
        })
    else:
        emit('resumable_scan_check', {'available': False})
```

#### 2.2 New Socket Event: Resume from Last Scan

```python
@socketio.on('resume_from_last_scan')
def resume_from_last_scan_event(data):
    """
    Load and emit assets from the most recent scan XML.
    """
    customer_id = data.get('customer_id')
    max_days = data.get('max_days', 7)

    if not customer_id:
        emit('resume_scan_error', {'error': 'No customer ID provided'})
        return

    xml_path, metadata = get_most_recent_scan_xml(customer_id, max_days)

    if not xml_path:
        emit('resume_scan_error', {'error': 'No recent scan found'})
        return

    # Parse XML to get assets
    assets = parse_scan_xml_for_assets(xml_path)

    if not assets:
        emit('resume_scan_error', {'error': 'No assets found in scan'})
        return

    # Emit assets with metadata indicating it's historical data
    emit('scan_results', {
        'hosts': assets,
        'total': len(assets),
        'is_historical': True,
        'scan_date': metadata.get('timestamp'),
        'target': metadata.get('target')
    })

    emit('scan_feedback', f"Loaded {len(assets)} assets from scan on {metadata.get('timestamp')}")
```

### Phase 3: Frontend Changes (index.html)

#### 3.1 Modify Customer Identification Handler

```javascript
socket.on('customer_info', function(customer) {
    // ... existing customer display code ...

    // Check if there's a resumable scan for this customer
    if (customer.id && customer.id !== 'unknown') {
        socket.emit('check_resumable_scan', {
            customer_id: customer.id,
            max_days: 7  // Configurable
        });
    }
});
```

#### 3.2 Handle Resumable Scan Check Response

```javascript
socket.on('resumable_scan_check', function(data) {
    if (data.available) {
        // Show UI indicator that historical data is available
        showHistoricalDataBanner(data);

        // Auto-resume or prompt user (configurable)
        const autoResume = true;  // Could be a user setting

        if (autoResume) {
            socket.emit('resume_from_last_scan', {
                customer_id: currentCustomer.id,
                max_days: 7
            });
        } else {
            // Show "Load Last Scan" button
            showResumeButton(data);
        }
    }
});
```

#### 3.3 Add Visual Indicators for Historical Data

```javascript
function showHistoricalDataBanner(scanInfo) {
    const scanDate = new Date(scanInfo.scan_date);
    const now = new Date();
    const daysDiff = Math.floor((now - scanDate) / (1000 * 60 * 60 * 24));

    let bannerClass = 'info';
    let message = '';

    if (daysDiff === 0) {
        message = `Showing scan from today at ${scanDate.toLocaleTimeString()}`;
        bannerClass = 'success';
    } else if (daysDiff === 1) {
        message = `Showing scan from yesterday at ${scanDate.toLocaleTimeString()}`;
        bannerClass = 'warning';
    } else {
        message = `Showing scan from ${daysDiff} days ago (${scanDate.toLocaleDateString()})`;
        bannerClass = 'warning-strong';
    }

    // Display banner above asset table
    const banner = document.createElement('div');
    banner.className = `scan-history-banner ${bannerClass}`;
    banner.innerHTML = `
        <span class="icon">📅</span>
        <span class="message">${message}</span>
        <span class="details">${scanInfo.total_hosts} hosts | ${scanInfo.duration}</span>
        <button onclick="runNewScan()" class="btn-small">Run New Scan</button>
    `;

    // Insert before asset table
    const tableContainer = document.getElementById('results-container');
    tableContainer.insertBefore(banner, tableContainer.firstChild);
}
```

#### 3.4 Modify Asset Display to Show Historical Indicator

```javascript
socket.on('scan_results', function(data) {
    if (data.is_historical) {
        // Add visual indicator that this is historical data
        document.getElementById('scan-status').innerHTML =
            `<span class="historical-badge">📅 Historical Data</span>
             Scanned on: ${new Date(data.scan_date).toLocaleString()}`;

        // Add subtle background tint to table
        document.getElementById('results-table').classList.add('historical-data');
    }

    // ... existing code to populate table ...
    populateTableWithResults(data.hosts);
});
```

### Phase 4: CSS for Visual Indicators

```css
/* Historical data indicators */
.scan-history-banner {
    padding: 12px 20px;
    margin-bottom: 16px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 14px;
}

.scan-history-banner.success {
    background: rgba(133, 146, 98, 0.1);  /* Olive tint */
    border-left: 4px solid #85926;
}

.scan-history-banner.warning {
    background: rgba(255, 193, 7, 0.15);
    border-left: 4px solid #ffc107;
}

.scan-history-banner.warning-strong {
    background: rgba(255, 152, 0, 0.2);
    border-left: 4px solid #ff9800;
}

.historical-badge {
    background: rgba(133, 146, 98, 0.2);
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
}

#results-table.historical-data {
    background: rgba(133, 146, 98, 0.03);
}

.btn-small {
    padding: 6px 12px;
    font-size: 13px;
    border-radius: 4px;
    background: #85926;
    color: white;
    border: none;
    cursor: pointer;
}

.btn-small:hover {
    background: #6d7a4f;
}
```

---

## Enhanced Features Beyond Basic Resume

### 1. Scan History Viewer

Add ability to view multiple historical scans:

```python
@socketio.on('get_scan_history')
def get_scan_history_event(data):
    """Get list of all recent scans for a customer"""
    customer_id = data.get('customer_id')
    max_scans = data.get('limit', 10)

    # ... find and return list of scans with metadata ...
```

### 2. Diff Between Scans

Compare current assets with previous scan:

```python
def compare_scans(current_assets, previous_assets):
    """
    Compare two asset lists and identify changes:
    - New hosts
    - Removed hosts
    - Changed ports/services
    """
    # ... implementation ...
```

### 3. TTL/Time-to-Live Display

Show how "fresh" the data is with color coding:
- Green: < 1 day old
- Yellow: 1-3 days old
- Orange: 3-7 days old
- Red: > 7 days old

### 4. Auto-Refresh Suggestion

If data is older than threshold, show "Data is X days old. Run new scan?" prompt.

---

## Configuration Options

Add to `app.py` or settings:

```python
# Asset resumption settings
ASSET_RESUME_CONFIG = {
    'enabled': True,
    'max_days': 7,              # Don't auto-resume if older than 7 days
    'auto_resume': True,        # Auto-load vs prompt user
    'show_age_indicator': True, # Show how old the data is
    'color_code_by_age': True,  # Visual indication of data age
}
```

---

## Benefits

1. **Instant Asset Display** - No wait for scan when returning to a network
2. **Reduced Scan Load** - Don't re-scan unless needed
3. **Better UX** - Users see context immediately
4. **Bandwidth Savings** - Fewer scans = less network traffic
5. **Historical Context** - Can compare current vs previous state
6. **Data Continuity** - Maintains asset visibility across sessions

---

## Implementation Estimate

### Phase 1 (XML Parser): 2-3 hours
- XML parsing function
- Get most recent scan function
- Testing with existing XML files

### Phase 2 (Backend Events): 1-2 hours
- Socket event handlers
- Integration with customer identification

### Phase 3 (Frontend): 3-4 hours
- UI indicators
- Historical data banner
- Resume button/auto-load logic

### Phase 4 (Polish): 2-3 hours
- CSS styling
- Configuration options
- Testing and refinement

**Total: 8-12 hours of development**

---

## Testing Checklist

- [ ] XML parser handles all host variations
- [ ] Correctly identifies most recent scan
- [ ] Respects max_days threshold
- [ ] Visual indicators display correctly
- [ ] Auto-resume works on customer identification
- [ ] Manual resume button functions
- [ ] Historical data clearly distinguished from fresh scans
- [ ] "Run New Scan" button works
- [ ] No errors when no historical data exists
- [ ] Performance is acceptable with large scan files
- [ ] Works with both auto and manual customer identification

---

## Next Steps

1. ✅ Verify XML contains all needed data (COMPLETE)
2. Implement XML parser function
3. Add socket events for resumption
4. Update frontend to handle historical data
5. Add visual indicators
6. Test with real scan data
7. Deploy and gather user feedback

---

## Conclusion

**Recommendation: PROCEED with implementation**

The XML files contain 100% of the data needed to resume asset display. This feature is highly feasible and will significantly improve user experience with minimal technical risk.

All the necessary infrastructure already exists:
- ✅ XML files with complete asset data
- ✅ Metadata files with timestamps
- ✅ Organized scan directory structure
- ✅ Customer identification system

We just need to wire it together with XML parsing and UI updates!
