# GitHub Issue: Feature Request - Pause and Resume Scan Functionality

## Title: Feature: Pause and Resume Scan Functionality

## Summary:
- Add ability to pause long-running network scans mid-operation
- Resume scans from the exact point where they were paused
- Preserve scan progress and results across pause/resume cycles
- Provide user controls for managing scan execution state

## Problem Statement:
Current scanning operations run continuously until completion. For long network scans or when users need to temporarily halt operations (system maintenance, network issues, user needs), there's no way to pause and resume scans. This leads to either:
- Aborted scans requiring complete restart
- Unnecessary resource consumption during unwanted scan periods
- Lost progress when scans must be interrupted

## Proposed Solution:

### 1. Scan State Management
- Implement comprehensive scan state tracking (running, paused, resuming, completed)
- Store scan progress in persistent storage for recovery
- Maintain scan parameters and discovered hosts across pause/resume cycles

### 2. Pause Functionality
- Add "Pause Scan" button during active scanning
- Gracefully halt current scan operations
- Save current progress and discovered data
- Update UI to reflect paused state

### 3. Resume Functionality
- Add "Resume Scan" button for paused scans
- Restore scan parameters and progress from saved state
- Continue scanning from last processed target
- Maintain scan timing and statistics

### 4. Progress Persistence
- Save discovered hosts and their states
- Track scan timing and performance metrics
- Preserve scan configuration and parameters
- Store partial results for immediate display

## Implementation Details:

### Backend Changes (app.py)
1. **Scan State Manager**
   ```python
   class ScanStateManager:
       def __init__(self):
           self.scan_states = {}  # scan_id -> state dict
           self.state_file = BASE_DIR / "data" / "scan_states.json"

       def save_scan_state(self, scan_id, state_data):
           """Save scan progress to persistent storage"""
           self.scan_states[scan_id] = {
               'status': state_data.get('status', 'unknown'),
               'start_time': state_data.get('start_time'),
               'pause_time': state_data.get('pause_time'),
               'progress': state_data.get('progress', {}),
               'targets_completed': state_data.get('targets_completed', []),
               'targets_remaining': state_data.get('targets_remaining', []),
               'results': state_data.get('results', []),
               'scan_config': state_data.get('scan_config', {})
           }
           self._persist_states()

       def load_scan_state(self, scan_id):
           """Load scan state from persistent storage"""
           return self.scan_states.get(scan_id)

       def pause_scan(self, scan_id):
           """Pause an active scan"""
           # Implementation...

       def resume_scan(self, scan_id):
           """Resume a paused scan"""
           # Implementation...
   ```

2. **Enhanced Scan Functions**
   - Modify `start_scan()` to support resume functionality
   - Add pause/resume handlers for Socket.IO events
   - Implement incremental result saving during long scans

3. **New Socket Events**
   - `scan_paused` - Notify UI of scan pause with progress data
   - `scan_resumed` - Signal scan resumption
   - `scan_progress_saved` - Confirm progress persistence
   - `scan_state_loaded` - Send saved state data to UI

### Frontend Changes (templates/index.html)
1. **Scan Control Enhancement**
   ```html
   <!-- Enhanced Scan Controls -->
   <div id="scan-controls" class="flex flex-wrap gap-3">
       <button id="start-scan-btn" class="inline-flex items-center justify-center gap-2 rounded-full bg-olive-950 text-white hover:bg-olive-800 font-medium py-2 px-5 text-sm transition-colors">
           <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
               <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h1.586a1 1 0 01.707.293l.707.707A1 1 0 0012.414 11H15m2 0h1.586a1 1 0 01.707.293l.707.707A1 1 0 0020.414 12H21"/>
           </svg>
           Start Scan
       </button>

       <button id="pause-scan-btn" class="hidden inline-flex items-center justify-center gap-2 rounded-full bg-amber-600 text-white hover:bg-amber-700 font-medium py-2 px-5 text-sm transition-colors">
           <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
               <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
           </svg>
           Pause Scan
       </button>

       <button id="resume-scan-btn" class="hidden inline-flex items-center justify-center gap-2 rounded-full bg-green-600 text-white hover:bg-green-700 font-medium py-2 px-5 text-sm transition-colors">
           <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
               <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h1.586a1 1 0 01.707.293l.707.707A1 1 0 0012.414 11H15m2 0h1.586a1 1 0 01.707.293l.707.707A1 1 0 0020.414 12H21"/>
           </svg>
           Resume Scan
       </button>

       <button id="stop-scan-btn" class="inline-flex items-center justify-center rounded-full bg-red-600 text-white hover:bg-red-700 font-medium py-2 px-4 text-sm transition-colors">
           Stop Scan
       </button>
   </div>
   ```

2. **Progress Indicators**
   - Add pause/resume status to scan progress cards
   - Show saved progress percentage for resumed scans
   - Display time spent in paused state

3. **State Management**
   ```javascript
   class ScanController {
       constructor() {
           this.currentScanId = null;
           this.scanState = 'idle'; // idle, running, paused, resuming
           this.savedProgress = {};
           this.initializeControls();
       }

       pauseScan() {
           socket.emit('pause_scan', { scan_id: this.currentScanId });
           this.updateUI('paused');
       }

       resumeScan() {
           socket.emit('resume_scan', { scan_id: this.currentScanId });
           this.updateUI('resuming');
       }

       updateUI(state) {
           this.scanState = state;
           // Update button visibility and states
           this.updateControlButtons();
           this.updateProgressIndicators();
       }
   }
   ```

### Data Persistence Structure
```json
{
  "scan_states": {
    "scan_20260109143045": {
      "status": "paused",
      "start_time": "2026-01-09T14:30:45Z",
      "pause_time": "2026-01-09T14:45:12Z",
      "progress": {
        "percentage": 65,
        "hosts_completed": 13,
        "hosts_total": 20,
        "current_target": "192.168.1.15"
      },
      "targets_completed": [
        "192.168.1.1",
        "192.168.1.2"
      ],
      "targets_remaining": [
        "192.168.1.15",
        "192.168.1.16"
      ],
      "results": [...],
      "scan_config": {
        "target": "192.168.1.0/24",
        "scan_type": "quick_scan",
        "timing_template": "T3"
      }
    }
  }
}
```

## User Experience Flow:

### Pause Scenario
1. User initiates network scan
2. Scan runs normally showing progress
3. User clicks "Pause Scan" button
4. System gracefully halts current operations
5. Progress is saved to persistent storage
6. UI updates to show paused state with resume option
7. Scan can be resumed at any time

### Resume Scenario
1. User clicks "Resume Scan" on paused scan
2. System loads saved scan state
3. UI shows "Resuming..." status
4. Scan continues from last processed target
5. Progress indicators update seamlessly
6. All timing and statistics continue from pause point

### Long-Running Scan Management
1. Scan automatically saves progress periodically
2. User can pause during lunch break or maintenance
3. System remains stable during pause periods
4. Resume picks up exactly where it left off
5. No duplicate scanning of completed targets

## Benefits:
1. **Flexibility**: Pause scans for system maintenance or user needs
2. **Efficiency**: Avoid restarting long scans from beginning
3. **Resource Management**: Control when scanning consumes resources
4. **Reliability**: Graceful handling of interruptions
5. **User Control**: Full control over scan execution timing

## Acceptance Criteria:
1. ✅ Scans can be paused during any phase (quick, deep, comprehensive)
2. ✅ Pause operation completes within 30 seconds
3. ✅ Scan progress is fully preserved across pause/resume cycles
4. ✅ Resume continues from exact point of pause (no duplicate work)
5. ✅ UI clearly indicates scan state (running, paused, resuming)
6. ✅ Progress indicators update correctly after resume
7. ✅ Scan timing and statistics continue accurately
8. ✅ Emergency stop functionality still works
9. ✅ Multiple pause/resume cycles supported
10. ✅ Scan state persists across application restarts

## Security Considerations:
- Secure storage of scan state data
- No sensitive scan data in logs during pause operations
- Proper cleanup of temporary scan state files
- Access controls for resume operations

## Technical Notes:
- Implement as background thread with proper signal handling
- Use atomic file operations for state persistence
- Handle network timeouts gracefully during resume
- Support for both manual and automatic pause triggers
- Integration with existing scan cancellation logic

---

## Implementation Priority:
1. **Phase 1**: Basic pause/resume framework and state persistence
2. **Phase 2**: Enhanced UI controls and progress indicators
3. **Phase 3**: Advanced features (auto-pause, scheduling integration)
4. **Phase 4**: Performance optimization and edge case handling

This feature provides essential control over long-running network scans, allowing users to manage scanning operations according to their operational needs and constraints.