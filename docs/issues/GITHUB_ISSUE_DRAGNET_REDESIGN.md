# GitHub Issue: Feature Request - Redesign Dragnet Scan Card as Settings & Change Monitoring Hub

## Title: Feature: Redesign Dragnet Scan Card as Settings & Change Monitoring Hub

## Summary:
- Transform the unused "Dragnet Scan" card into a settings and monitoring hub
- Add toggle for daily automated scans with scheduling controls
- Implement change highlighting from previous scans
- Create compact monitoring interface that activates after deep scans complete
- Differentiate from comprehensive "Generate Report" functionality

## Problem Statement:
The current "Dragnet Scan" card is a third scan statistics card that doesn't have a clear purpose or functionality. It appears alongside Quick Scan and Deep Scan cards but lacks meaningful content or utility. Meanwhile, users need:

1. **Settings Access**: Easy access to scan scheduling and automation settings
2. **Change Monitoring**: Visual indication of network changes between scans
3. **Compact Monitoring**: Lightweight monitoring that doesn't interfere with primary scanning
4. **Post-Scan Analysis**: Analysis that runs after main scanning operations complete

The distinction from "Generate Report" (which comprehensively scans entire subnets) is important - dragnet functionality should be more targeted and efficient.

## Proposed Solution:

### 1. Card Redesign: Settings & Monitoring Hub
Transform the dragnet scan card into a multi-purpose settings and monitoring interface that provides:
- Daily scan scheduling controls
- Change detection and highlighting
- Post-scan analysis capabilities
- Compact, non-intrusive monitoring

### 2. Daily Scan Toggle Integration
- Prominent toggle for enabling/disabling automated daily scans
- Quick access to scheduling preferences
- Status indicator for next scheduled scan
- One-click access to full scheduling configuration

### 3. Change Highlighting System
- Compare current scan results with previous scans
- Highlight new devices, changed services, disappeared hosts
- Visual indicators for significant changes
- Historical trend analysis

### 4. Post-Scan Activation
- Card becomes active after deep scans complete
- Runs lightweight analysis on scan results
- Monitors for changes without full rescanning
- Provides ongoing network health indicators

## Implementation Details:

### Backend Changes (app.py)
1. **Change Detection Engine**
   ```python
   class ChangeDetector:
       def __init__(self):
           self.baseline_file = BASE_DIR / "data" / "scan_baseline.json"
           self.load_baseline()

       def detect_changes(self, current_results):
           """Compare current scan with baseline and identify changes"""
           changes = {
               'new_hosts': [],
               'changed_hosts': [],
               'disappeared_hosts': [],
               'service_changes': [],
               'significant_changes': []
           }

           # Compare logic...
           return changes

       def update_baseline(self, results):
           """Update baseline with current results"""
           # Implementation...

       def get_change_summary(self):
           """Get summary of changes since last scan"""
           # Implementation...
   ```

2. **Dragnet Analysis Service**
   ```python
   class DragnetAnalyzer:
       def __init__(self):
           self.change_detector = ChangeDetector()
           self.is_active = False

       def start_post_scan_analysis(self, scan_results):
           """Begin dragnet analysis after main scans complete"""
           self.is_active = True

           # Lightweight analysis of results
           changes = self.change_detector.detect_changes(scan_results)

           # Generate insights and recommendations
           insights = self.generate_insights(changes)

           return {
               'changes': changes,
               'insights': insights,
               'recommendations': self.generate_recommendations(changes)
           }

       def generate_insights(self, changes):
           """Generate actionable insights from changes"""
           # Implementation...
   ```

3. **New Socket Events**
   - `dragnet_analysis_start` - Signal dragnet analysis beginning
   - `dragnet_changes_detected` - Send detected changes to UI
   - `dragnet_insights_ready` - Provide analysis insights
   - `daily_scan_toggled` - Update daily scan status

### Frontend Changes (templates/index.html)
1. **Redesigned Dragnet Card**
   ```html
   <div class="bg-olive-50 p-4 rounded-xl shadow-sm border border-olive-300">
       <div class="flex items-center justify-between mb-3">
           <div class="flex items-center space-x-2">
               <h2 class="text-lg font-display italic text-olive-900">Network Monitor</h2>
               <span id="dragnet-status" class="px-2 py-1 text-xs rounded-full bg-olive-200 text-olive-800">Ready</span>
           </div>
           <div class="flex items-center space-x-2">
               <label class="flex items-center cursor-pointer">
                   <input type="checkbox" id="daily-scan-toggle" class="sr-only peer">
                   <div class="relative w-9 h-5 bg-olive-300 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-olive-400 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-olive-600"></div>
                   <span class="ml-2 text-sm text-olive-700">Daily Scans</span>
               </label>
           </div>
       </div>

       <!-- Change Summary -->
       <div id="change-summary" class="hidden mb-3 p-3 bg-amber-50 border border-amber-200 rounded-lg">
           <div class="flex items-center justify-between mb-2">
               <h3 class="text-sm font-semibold text-amber-800">Network Changes Detected</h3>
               <button id="view-changes-btn" class="text-xs text-amber-700 hover:text-amber-900 underline">View Details</button>
           </div>
           <div class="grid grid-cols-2 gap-2 text-xs">
               <div class="flex justify-between">
                   <span class="text-amber-700">New Hosts:</span>
                   <span id="new-hosts-count" class="font-semibold">0</span>
               </div>
               <div class="flex justify-between">
                   <span class="text-amber-700">Changed:</span>
                   <span id="changed-hosts-count" class="font-semibold">0</span>
               </div>
               <div class="flex justify-between">
                   <span class="text-amber-700">Disappeared:</span>
                   <span id="disappeared-hosts-count" class="font-semibold">0</span>
               </div>
               <div class="flex justify-between">
                   <span class="text-amber-700">Service Changes:</span>
                   <span id="service-changes-count" class="font-semibold">0</span>
               </div>
           </div>
       </div>

       <!-- Daily Scan Status -->
       <div id="daily-scan-status" class="mb-3 p-2 bg-olive-100 rounded text-xs">
           <div class="flex justify-between items-center">
               <span class="text-olive-700">Next scan:</span>
               <span id="next-scan-time" class="font-mono text-olive-900">Not scheduled</span>
           </div>
       </div>

       <!-- Monitoring Stats -->
       <div class="grid grid-cols-3 gap-2 text-xs">
           <div class="text-center p-2 bg-white rounded border border-olive-200">
               <div class="font-semibold text-olive-900" id="monitor-uptime">99.9%</div>
               <div class="text-olive-600">Uptime</div>
           </div>
           <div class="text-center p-2 bg-white rounded border border-olive-200">
               <div class="font-semibold text-olive-900" id="monitor-changes">+2</div>
               <div class="text-olive-600">Changes</div>
           </div>
           <div class="text-center p-2 bg-white rounded border border-olive-200">
               <div class="font-semibold text-olive-900" id="monitor-alerts">0</div>
               <div class="text-olive-600">Alerts</div>
           </div>
       </div>

       <!-- Compact Analysis Progress (shown during analysis) -->
       <div id="dragnet-progress" class="hidden mt-3">
           <div class="flex justify-between text-xs text-olive-600 mb-1">
               <span>Analyzing network changes...</span>
               <span id="analysis-progress">0%</span>
           </div>
           <div class="w-full bg-olive-200 rounded-full h-1.5">
               <div id="analysis-bar" class="bg-olive-600 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
           </div>
       </div>
   </div>
   ```

2. **Settings Integration**
   - Daily scan toggle connects to scheduling system
   - Change highlighting preferences
   - Monitoring sensitivity settings

3. **JavaScript Enhancement**
   ```javascript
   class NetworkMonitor {
       constructor() {
           this.changeDetector = new ChangeDetector();
           this.dailyScanEnabled = false;
           this.initializeUI();
           this.loadSettings();
       }

       initializeUI() {
           // Set up daily scan toggle
           document.getElementById('daily-scan-toggle').addEventListener('change', (e) => {
               this.toggleDailyScans(e.target.checked);
           });

           // Change details modal trigger
           document.getElementById('view-changes-btn').addEventListener('click', () => {
               this.showChangeDetails();
           });
       }

       startDragnetAnalysis(results) {
           socket.emit('start_dragnet_analysis', { scan_results: results });
           this.showProgress();
       }

       showChangeSummary(changes) {
           // Update change counters
           document.getElementById('new-hosts-count').textContent = changes.new_hosts.length;
           document.getElementById('changed-hosts-count').textContent = changes.changed_hosts.length;
           // Show change summary if there are changes
           if (this.hasSignificantChanges(changes)) {
               document.getElementById('change-summary').classList.remove('hidden');
           }
       }
   }
   ```

### Data Structure for Change Detection
```json
{
  "baseline": {
    "timestamp": "2026-01-09T10:00:00Z",
    "hosts": {
      "192.168.1.1": {
        "mac": "00:11:22:33:44:55",
        "hostname": "router.local",
        "ports": [22, 80, 443],
        "services": ["SSH", "HTTP", "HTTPS"],
        "last_seen": "2026-01-09T10:00:00Z"
      }
    }
  },
  "changes": {
    "new_hosts": ["192.168.1.50"],
    "changed_hosts": ["192.168.1.10"],
    "disappeared_hosts": ["192.168.1.25"],
    "service_changes": [
      {
        "host": "192.168.1.15",
        "changes": ["Added port 3389 (RDP)"]
      }
    ]
  }
}
```

## User Experience Flow:

### Primary Scanning Complete
1. User runs quick scan + deep scan (normal workflow)
2. After deep scan completes, dragnet card becomes active
3. Lightweight analysis begins automatically
4. Change detection runs against previous baseline

### Change Detection & Display
1. System compares current results with saved baseline
2. Identifies new/changed/disappeared hosts and services
3. Updates change summary in compact card format
4. Highlights significant changes with visual indicators

### Daily Scan Integration
1. Toggle enables/disables automated daily scanning
2. Shows next scheduled scan time
3. Provides quick access to scheduling settings
4. Visual feedback for scan status

### Settings Access
1. Card serves as gateway to scan automation settings
2. Change highlighting preferences
3. Monitoring sensitivity controls
4. Baseline management options

## Benefits:
1. **Repurposed UI**: Gives meaningful function to unused card space
2. **Continuous Monitoring**: Lightweight change detection between scans
3. **Settings Access**: Convenient access to automation controls
4. **Change Awareness**: Immediate visibility of network changes
5. **Resource Efficient**: Runs after primary scans, minimal additional load

## Acceptance Criteria:
1. ✅ Dragnet card transforms from unused scan stats to active monitoring hub
2. ✅ Daily scan toggle integrates with scheduling system (Issue #6)
3. ✅ Change detection highlights differences from previous scans
4. ✅ Card activates after deep scans complete (post-scan analysis)
5. ✅ Compact design fits within existing card layout
6. ✅ Clear distinction from comprehensive "Generate Report" functionality
7. ✅ Visual indicators for new/changed/disappeared devices
8. ✅ Settings access for scan automation preferences
9. ✅ Progress indication during dragnet analysis
10. ✅ Baseline management and update capabilities

## Security Considerations:
- Change detection data doesn't expose sensitive information
- Baseline data stored securely
- Access controls for settings modifications
- Audit logging of monitoring activities

## Technical Notes:
- Integrates with existing scan result storage
- Leverages change detection from Issue #1 (asset resume)
- Complements but doesn't duplicate Issue #6 (daily scheduling)
- Uses existing UI patterns and styling
- Minimal performance impact on primary scanning

---

## Implementation Priority:
1. **Phase 1**: Basic card redesign and daily scan toggle
2. **Phase 2**: Change detection system integration
3. **Phase 3**: Post-scan analysis automation
4. **Phase 4**: Advanced monitoring features and insights

This redesign transforms an unused UI element into a valuable network monitoring and settings hub, providing continuous change awareness while maintaining the efficiency distinction from comprehensive subnet scanning.