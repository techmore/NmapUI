# Auto Customer Detection Audit & Implementation Plan

**Date**: 2026-01-08
**Objective**: Ensure automatic customer detection works on startup and automatically captures network fingerprint data when adding new customers

---

## Current State Analysis

### ✅ What's Working

1. **Traceroute Collection on Startup** (app.py:78-171)
   - ✅ Runs traceroute to 1.1.1.1 on app startup
   - ✅ Fetches public IP from api.ipify.org (line 86)
   - ✅ Parses all hops (private and public)
   - ✅ Calculates exit IP (last hop)
   - ✅ Stores in global `network_key` dict with all required fields

2. **Customer Fingerprinting Engine** (customer_fingerprint.py)
   - ✅ Comprehensive scoring algorithm
   - ✅ Exit IP matching (exact, range, dynamic)
   - ✅ Public IP matching
   - ✅ Hop pattern analysis
   - ✅ Latency profiling
   - ✅ Network size detection
   - ✅ Weighted scoring system (exit_ip: 30%, hop_pattern: 40%, latency: 20%, network_size: 10%)

3. **Automatic Customer Matching** (app.py:148-162)
   - ✅ Runs `customer_fingerprinter.match_customer()` after traceroute
   - ✅ Sets global `current_customer` variable
   - ✅ Saves scan result to history (app.py:158)
   - ✅ Logs confidence score

4. **Customer Storage** (customers.yaml)
   - ✅ YAML-based customer database
   - ✅ Supports multiple fingerprints per customer
   - ✅ Network configuration (public_ip, exit_ips, private_ranges, gateway_pattern)
   - ✅ Metadata (location, ISP, connection_type, network_size)

---

## ❌ What's NOT Working

### Critical Issue #1: Manual Customer Form Doesn't Auto-Capture Current Network Data

**Problem**: When a user adds a new customer via the form, they must manually enter:
- Public IP pattern
- Exit IP pattern
- Gateway pattern
- Private IP ranges
- Hop count
- Connection type

**Expected Behavior**: Form should be pre-filled with the CURRENT network data that was just captured during traceroute.

**Current Form Fields** (index.html:184-245):
```html
- Customer Name (manual)
- Customer ID (manual)
- Description (manual)
- Location (manual)
- Connection Type (dropdown, not auto-detected)
- Gateway Pattern (manual, NOT from network_key.hops[0].ip)
- Exit IP Pattern (manual, NOT from network_key.exit_ip)
- Hop Count Range (manual, NOT from network_key.total_hops)
- Private IP Ranges (manual, NOT from network_key.private_hops)
```

**Impact**: Users must remember and manually type network details that the system ALREADY COLLECTED. This is error-prone and defeats the purpose of auto-detection.

---

### Critical Issue #2: No Auto-Selection of Matched Customer in Dropdown

**Problem**: After traceroute completes and identifies a customer (stored in `current_customer`), the dropdown selection is NOT automatically updated to reflect the matched customer.

**Current Flow**:
1. App starts → traceroute runs → customer matched (e.g., "TechCorp HQ" with 0.85 confidence)
2. Global `current_customer` is set to matched customer
3. ✅ Backend emits `customer_info` event (app.py:667-669)
4. ❌ Frontend receives event BUT doesn't update the dropdown selection

**Expected Behavior**:
- When `customer_info` event is received, the dropdown should auto-select the matched customer
- A visual indicator should show the confidence level (e.g., "TechCorp HQ (85% confident)")

**Current Frontend Code** (index.html:571-608):
```javascript
socket.on('customer_info', data => {
    // Updates customer card display
    // BUT does NOT update the dropdown selection
    // Dropdown still shows "Auto-detect network..."
});
```

---

### Critical Issue #3: No Real-Time Network Update in Form

**Problem**: If a user opens the "Add Customer" form, the fields are empty even though `network_key` has all the data.

**Missing Functionality**:
- No button to "Use Current Network Data"
- No auto-population of form fields
- No visual display of what the system detected

---

## Implementation Plan

### Phase 1: Auto-Populate Customer Form with Current Network Data

**Goal**: When user opens "Add Customer" form, pre-fill network-related fields with data from `network_key`.

**Changes Needed**:

#### 1.1 Update Frontend: Add "Use Current Network" Button (index.html)

Add button above form fields:
```html
<div class="bg-olive-50 p-4 rounded-lg mb-4 border border-olive-200">
    <div class="flex items-center justify-between">
        <div>
            <p class="text-sm font-medium text-olive-900">Current Network Detected</p>
            <p class="text-xs text-olive-600">Exit IP: <span id="form-exit-ip">--</span> | Hops: <span id="form-hop-count">--</span></p>
        </div>
        <button onclick="populateFromCurrentNetwork()"
                class="px-4 py-2 bg-olive-600 text-white rounded-lg hover:bg-olive-700 text-sm">
            Use Current Network Data
        </button>
    </div>
</div>
```

#### 1.2 Add JavaScript Function to Populate Form (index.html)

```javascript
function populateFromCurrentNetwork() {
    // Request current network_key from backend
    socket.emit('get_network_key');
}

socket.on('network_key', data => {
    // Update form preview
    document.getElementById('form-exit-ip').textContent = data.exit_ip || '--';
    document.getElementById('form-hop-count').textContent = data.total_hops || '--';

    // Populate form fields if form is open
    if (!document.getElementById('add-customer-form').classList.contains('hidden')) {
        // Gateway: First private hop IP
        if (data.private_hops && data.private_hops.length > 0) {
            document.getElementById('cust-gateway').value = data.private_hops[0].ip;
        }

        // Exit IP: Convert to pattern (e.g., 203.0.113.45 → 203.0.113.*)
        if (data.exit_ip) {
            const exitParts = data.exit_ip.split('.');
            const exitPattern = `${exitParts[0]}.${exitParts[1]}.${exitParts[2]}.*`;
            document.getElementById('cust-exit-pattern').value = exitPattern;
        }

        // Hop count: Convert to range (e.g., 5 → 4-6)
        if (data.total_hops) {
            const hopRange = `${data.total_hops - 1}-${data.total_hops + 1}`;
            document.getElementById('cust-hop-count').value = hopRange;
        }

        // Auto-detect connection type based on network characteristics
        const connectionType = detectConnectionType(data);
        document.getElementById('cust-connection-type').value = connectionType;

        // Private ranges: Extract from private hops
        const privateRanges = extractPrivateRanges(data.private_hops);
        document.getElementById('cust-private-ranges').value = privateRanges;
    }
});

function detectConnectionType(networkKey) {
    const hops = networkKey.hops || [];
    const privateHops = networkKey.private_hops || [];

    if (hops.length > 5) return 'vpn';
    if (privateHops.length <= 2) return 'residential';
    if (privateHops.length > 4) return 'corporate';
    return 'direct';
}

function extractPrivateRanges(privateHops) {
    if (!privateHops || privateHops.length === 0) return '';

    // Detect common ranges
    const ranges = new Set();
    privateHops.forEach(hop => {
        if (hop.ip.startsWith('192.168.')) ranges.add('192.168.0.0/16');
        if (hop.ip.startsWith('10.')) ranges.add('10.0.0.0/8');
        if (hop.ip.startsWith('172.')) ranges.add('172.16.0.0/12');
    });

    return Array.from(ranges).join(',');
}
```

#### 1.3 Update Backend: Add get_network_key SocketIO Handler (app.py)

```python
@socketio.on("get_network_key")
def get_network_key_event():
    """Send current network_key to client"""
    emit("network_key", network_key)
```

---

### Phase 2: Auto-Select Matched Customer in Dropdown

**Goal**: After customer matching completes, automatically update the dropdown to reflect the matched customer.

**Changes Needed**:

#### 2.1 Update Frontend: Auto-Select on customer_info Event (index.html)

Modify existing `customer_info` socket handler:
```javascript
socket.on('customer_info', data => {
    console.log('Customer info received:', data);

    // Update customer card display (EXISTING)
    document.getElementById('customer-name').textContent = data.name || 'Unknown Network';
    const confidencePercent = ((data.confidence || 0) * 100).toFixed(0);
    document.getElementById('customer-confidence').textContent = `${confidencePercent}%`;

    // NEW: Auto-select in dropdown if confidence is above threshold
    const dropdown = document.getElementById('current-customer');
    if (data.id && data.id !== 'unknown' && data.confidence >= 0.7) {
        // Find matching option in dropdown
        const option = Array.from(dropdown.options).find(opt => opt.value === data.id);
        if (option) {
            dropdown.value = data.id;

            // Update option text to show confidence
            option.textContent = `${data.name} (${confidencePercent}% confident)`;

            // Visual feedback
            dropdown.classList.add('border-olive-500', 'border-2');
            setTimeout(() => {
                dropdown.classList.remove('border-olive-500', 'border-2');
            }, 2000);
        }
    } else {
        // Reset to auto-detect if confidence is low
        dropdown.value = '';
    }
});
```

#### 2.2 Update Backend: Include Confidence in customer_info Emission (app.py)

Current code at line 667-669 already sends `current_customer` which includes confidence. ✅ No change needed.

---

### Phase 3: Add Visual Indicator for Auto-Detection Status

**Goal**: Show user when auto-detection is running, complete, or failed.

**Changes Needed**:

#### 3.1 Add Status Indicator to Customer Card (index.html)

Add after customer dropdown (around line 145):
```html
<div id="detection-status" class="mt-2 hidden">
    <div class="flex items-center gap-2 text-sm">
        <span class="relative flex h-3 w-3">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-olive-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-3 w-3 bg-olive-500"></span>
        </span>
        <span id="detection-status-text" class="text-olive-700">Detecting network...</span>
    </div>
</div>
```

#### 3.2 Update Status on Events (index.html)

```javascript
// Show detection in progress on startup
socket.on('connect', () => {
    showDetectionStatus('Analyzing network...', 'loading');
});

// Update on traceroute complete
socket.on('network_key', data => {
    if (data.total_hops > 0) {
        showDetectionStatus('Network analyzed', 'success');
    }
});

// Update on customer matched
socket.on('customer_info', data => {
    if (data.confidence >= 0.7) {
        showDetectionStatus(`Matched: ${data.name} (${(data.confidence * 100).toFixed(0)}%)`, 'success');
    } else {
        showDetectionStatus('No match found - manual selection required', 'warning');
    }
});

function showDetectionStatus(message, type) {
    const statusDiv = document.getElementById('detection-status');
    const statusText = document.getElementById('detection-status-text');

    statusDiv.classList.remove('hidden');
    statusText.textContent = message;

    // Update indicator style
    const indicator = statusDiv.querySelector('.relative.flex');
    indicator.className = type === 'loading' ?
        'relative flex h-3 w-3' : // pulsing
        'relative flex h-3 w-3 opacity-0'; // hidden

    // Auto-hide after success
    if (type === 'success') {
        setTimeout(() => statusDiv.classList.add('hidden'), 5000);
    }
}
```

---

### Phase 4: Add "Auto-Detect Now" Manual Trigger

**Goal**: Allow users to manually re-run traceroute and customer detection.

**Changes Needed**:

#### 4.1 Add Button to Customer Card (index.html)

```html
<button onclick="rerunDetection()"
        class="text-sm text-olive-600 hover:text-olive-800 underline">
    Re-detect Network
</button>
```

#### 4.2 Add Frontend Function (index.html)

```javascript
function rerunDetection() {
    showDetectionStatus('Re-analyzing network...', 'loading');
    socket.emit('rerun_traceroute');
}
```

#### 4.3 Add Backend Handler (app.py)

```python
@socketio.on("rerun_traceroute")
def rerun_traceroute_event():
    """Manually re-run traceroute and customer detection"""
    try:
        # Run traceroute again
        run_traceroute()

        # Send updated data
        emit("network_key", network_key, broadcast=False)
        emit("customer_info", current_customer, broadcast=False)

    except Exception as e:
        emit("customer_error", f"Failed to re-run detection: {str(e)}")
```

---

## Testing Plan

### Test Case 1: Startup Auto-Detection
1. Start app: `sudo python3 app.py`
2. ✅ Verify traceroute runs automatically
3. ✅ Verify public IP is fetched
4. ✅ Verify customer is matched (check console logs)
5. ✅ Verify dropdown is auto-selected if confidence >= 70%
6. ✅ Verify customer card shows name and confidence

### Test Case 2: Add Customer with Auto-Populate
1. Start app and let auto-detection complete
2. Open "Add Customer" form
3. Click "Use Current Network Data" button
4. ✅ Verify gateway is pre-filled with first hop IP
5. ✅ Verify exit IP pattern is pre-filled (e.g., 203.0.113.*)
6. ✅ Verify hop count range is pre-filled (e.g., 4-6)
7. ✅ Verify connection type is auto-detected
8. ✅ Verify private ranges are auto-detected
9. Manually enter customer name and ID
10. Click "Add Customer"
11. ✅ Verify customer is saved to YAML with captured network data

### Test Case 3: Manual Re-Detection
1. App is running with a customer matched
2. Change network (e.g., switch WiFi or VPN)
3. Click "Re-detect Network" button
4. ✅ Verify new traceroute runs
5. ✅ Verify customer is re-matched
6. ✅ Verify dropdown updates if match changes

### Test Case 4: Low Confidence Scenario
1. Connect from unknown network
2. ✅ Verify dropdown stays at "Auto-detect network..."
3. ✅ Verify customer card shows "Unknown Network" with low confidence
4. ✅ Verify status indicator shows "No match found"
5. Open "Add Customer" form
6. ✅ Verify network data is still available to auto-populate

---

## Summary of Changes

### Files to Modify:

1. **templates/index.html**
   - Add "Current Network Detected" section to form
   - Add `populateFromCurrentNetwork()` function
   - Add `detectConnectionType()` helper
   - Add `extractPrivateRanges()` helper
   - Update `customer_info` socket handler for auto-selection
   - Add detection status indicator and functions
   - Add "Re-detect Network" button and handler

2. **app.py**
   - Add `get_network_key` SocketIO event handler
   - Add `rerun_traceroute` SocketIO event handler
   - (Optional) Update `customer_info` emission to include more details

3. **customers.yaml**
   - No changes needed (data structure already supports all fields)

4. **customer_fingerprint.py**
   - No changes needed (matching logic already works correctly)

---

## Expected Outcomes

After implementation:

✅ **On app startup**:
- Traceroute runs → network analyzed → customer matched → dropdown auto-selected → confidence displayed

✅ **When adding new customer**:
- Form pre-fills with current network data
- User only needs to add name, ID, description
- Network fingerprint is automatically captured accurately

✅ **User experience**:
- Clear visual feedback on detection status
- Ability to manually re-trigger detection
- Confidence scores visible everywhere
- Seamless workflow from detection to customer assignment

---

## Priority: HIGH

**Reasoning**: This is a core feature that significantly improves UX and reduces manual data entry errors. The backend infrastructure is already in place - we just need to connect it to the frontend properly.

**Estimated Implementation Time**: 2-3 hours

**Risk Level**: Low (mostly UI changes, existing logic is sound)

**Testing Time**: 1 hour
