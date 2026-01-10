# GitHub Issue: Feature Request - Daily Automated Scan Scheduling

## Title: Feature: Daily Automated Scan Scheduling with Time Windows

## Summary:
- Toggle for enabling automated daily scans
- Configurable day selection (include/exclude specific weekdays)
- Time windows for scan execution (start and stop times)
- Automatic scan execution within defined schedules
- Safety mechanisms to prevent runaway scans

## Problem Statement:
Network security requires regular monitoring, but manual scanning can be inconsistent or forgotten. Users need the ability to schedule automated scans that run during appropriate times while ensuring they complete within business hours or maintenance windows. The system should respect operational constraints while providing reliable, scheduled network assessment capabilities.

## Proposed Solution:

### 1. Daily Scan Toggle
- Master toggle to enable/disable all automated scanning
- Visual indicator when automated scanning is active
- Safety confirmation when enabling automated scans

### 2. Day Selection
- Checkbox interface for each day of the week (Monday-Sunday)
- Include/exclude specific days
- Holiday/special date exclusions
- One-time override capabilities

### 3. Time Window Configuration
- Start time selection (when automated scans can begin)
- Stop time selection (when scans must complete by)
- Multiple time windows per day support
- Business hours vs maintenance window modes

### 4. Automated Execution
- Background scheduling service
- Scan queue management
- Conflict resolution with manual scans
- Automatic report generation and storage

### 5. Safety & Monitoring
- Scan timeout enforcement
- Resource usage monitoring
- Failure notification and retry logic
- Manual override and emergency stop

## Implementation Details:

### Backend Changes (app.py)
1. **Scan Scheduler Service**
   ```python
   class AutomatedScanScheduler:
       def __init__(self):
           self.schedule_config = self.load_schedule_config()
           self.scan_queue = []
           self.is_active = False

       def load_schedule_config(self):
           return {
               'enabled': False,
               'days': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
               'time_windows': [
                   {'start': '09:00', 'end': '17:00', 'type': 'business_hours'}
               ],
               'target_networks': [],
               'scan_profile': 'quick_scan',
               'max_runtime': 3600,  # 1 hour
               'retry_attempts': 3,
               'notification_settings': {}
           }

       def check_schedule(self):
           """Check if current time matches schedule criteria"""
           now = datetime.now()
           current_day = now.strftime('%A').lower()
           current_time = now.strftime('%H:%M')

           if not self.schedule_config['enabled']:
               return False

           if current_day not in self.schedule_config['days']:
               return False

           # Check if within any time window
           for window in self.schedule_config['time_windows']:
               if window['start'] <= current_time <= window['end']:
                   return True

           return False

       def execute_scheduled_scan(self):
           """Execute scan according to schedule"""
           # Implementation details...
   ```

2. **New Socket Events**
   - `schedule_status` - Send current schedule configuration
   - `schedule_updated` - Notify of schedule changes
   - `automated_scan_starting` - Signal upcoming automated scan
   - `automated_scan_progress` - Show scan progress
   - `automated_scan_complete` - Report completion status
   - `schedule_conflict` - Handle conflicts with manual operations

3. **Configuration Persistence**
   - Store schedule settings in JSON configuration file
   - Backup and restore capabilities
   - Validation of schedule parameters

### Frontend Changes (templates/index.html)
1. **Schedule Configuration Panel**
   ```html
   <div id="scan-scheduler-panel" class="bg-olive-50 p-6 rounded-xl shadow-sm border border-olive-300">
       <div class="flex items-center justify-between mb-6">
           <h2 class="text-xl font-display italic text-olive-900">Automated Scan Scheduler</h2>
           <label class="flex items-center cursor-pointer">
               <input type="checkbox" id="scheduler-toggle" class="sr-only peer">
               <div class="relative w-11 h-6 bg-olive-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-olive-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-olive-600"></div>
               <span class="ml-3 text-sm font-medium text-olive-900">Enable Daily Scans</span>
           </label>
       </div>

       <!-- Day Selection -->
       <div class="mb-6">
           <h3 class="text-lg font-semibold text-olive-800 mb-3">Scan Days</h3>
           <div class="grid grid-cols-7 gap-2">
               <label class="flex items-center space-x-2 cursor-pointer">
                   <input type="checkbox" id="mon" class="rounded border-olive-300 text-olive-600 focus:ring-olive-500">
                   <span class="text-sm text-olive-700">Mon</span>
               </label>
               <!-- Similar for Tue, Wed, Thu, Fri, Sat, Sun -->
           </div>
       </div>

       <!-- Time Windows -->
       <div class="mb-6">
           <h3 class="text-lg font-semibold text-olive-800 mb-3">Time Windows</h3>
           <div id="time-windows" class="space-y-3">
               <div class="time-window-item flex items-center space-x-3 p-3 bg-white rounded-lg border border-olive-200">
                   <input type="time" class="border border-olive-300 rounded px-2 py-1 text-sm" value="09:00">
                   <span class="text-olive-600">to</span>
                   <input type="time" class="border border-olive-300 rounded px-2 py-1 text-sm" value="17:00">
                   <select class="border border-olive-300 rounded px-2 py-1 text-sm">
                       <option value="business_hours">Business Hours</option>
                       <option value="maintenance">Maintenance</option>
                       <option value="off_hours">Off Hours</option>
                   </select>
                   <button class="text-red-500 hover:text-red-700">×</button>
               </div>
           </div>
           <button class="mt-3 px-4 py-2 bg-olive-600 text-white rounded-lg hover:bg-olive-700 transition-colors">
               + Add Time Window
           </button>
       </div>

       <!-- Scan Settings -->
       <div class="mb-6">
           <h3 class="text-lg font-semibold text-olive-800 mb-3">Scan Configuration</h3>
           <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
               <div>
                   <label class="block text-sm font-medium text-olive-700 mb-1">Scan Type</label>
                   <select id="scan-type" class="w-full border border-olive-300 rounded-lg px-3 py-2">
                       <option value="quick_scan">Quick Scan</option>
                       <option value="deep_scan">Deep Scan</option>
                       <option value="comprehensive">Comprehensive</option>
                   </select>
               </div>
               <div>
                   <label class="block text-sm font-medium text-olive-700 mb-1">Max Runtime (minutes)</label>
                   <input type="number" id="max-runtime" class="w-full border border-olive-300 rounded-lg px-3 py-2" value="60" min="5" max="480">
               </div>
           </div>
       </div>

       <!-- Target Networks -->
       <div class="mb-6">
           <h3 class="text-lg font-semibold text-olive-800 mb-3">Target Networks</h3>
           <div id="target-networks" class="space-y-2">
               <div class="flex items-center space-x-2">
                   <input type="text" class="flex-1 border border-olive-300 rounded-lg px-3 py-2" placeholder="192.168.1.0/24" value="192.168.1.0/24">
                   <button class="text-red-500 hover:text-red-700">×</button>
               </div>
           </div>
           <button class="mt-2 px-4 py-2 bg-olive-600 text-white rounded-lg hover:bg-olive-700 transition-colors">
               + Add Network
           </button>
       </div>

       <!-- Status & Controls -->
       <div class="flex items-center justify-between pt-4 border-t border-olive-200">
           <div id="scheduler-status" class="text-sm text-olive-600">
               Scheduler: <span class="font-medium">Disabled</span>
           </div>
           <div class="flex space-x-3">
               <button id="test-schedule-btn" class="px-4 py-2 bg-olive-500 text-white rounded-lg hover:bg-olive-600 transition-colors">
                   Test Schedule
               </button>
               <button id="save-schedule-btn" class="px-4 py-2 bg-olive-600 text-white rounded-lg hover:bg-olive-700 transition-colors">
                   Save Settings
               </button>
           </div>
       </div>
   </div>
   ```

2. **Status Indicators**
   - Next scheduled scan time
   - Last scan execution status
   - Active scan progress for automated scans
   - Schedule conflict warnings

3. **JavaScript Integration**
   ```javascript
   class ScanScheduler {
       constructor() {
           this.config = {};
           this.nextScanTime = null;
           this.initializeUI();
           this.loadConfiguration();
       }

       loadConfiguration() {
           socket.emit('get_schedule_config');
       }

       saveConfiguration() {
           const config = {
               enabled: document.getElementById('scheduler-toggle').checked,
               days: this.getSelectedDays(),
               timeWindows: this.getTimeWindows(),
               scanType: document.getElementById('scan-type').value,
               maxRuntime: parseInt(document.getElementById('max-runtime').value),
               targetNetworks: this.getTargetNetworks()
           };

           socket.emit('update_schedule_config', config);
       }

       checkSchedule() {
           // Check if current time matches schedule
           socket.emit('check_schedule_status');
       }
   }
   ```

### Configuration Options
- **Schedule Settings**
  - Master enable/disable toggle
  - Day selection (individual checkboxes)
  - Multiple time windows per day
  - Time zone considerations

- **Scan Parameters**
  - Scan type (quick, deep, comprehensive)
  - Maximum runtime limits
  - Target network ranges
  - Scan intensity settings

- **Safety & Monitoring**
  - Timeout enforcement
  - Resource usage limits
  - Failure retry logic
  - Notification settings

### Safety Features
1. **Timeout Protection**: All automated scans have maximum runtime limits
2. **Resource Monitoring**: CPU/memory usage monitoring with thresholds
3. **Conflict Detection**: Prevent conflicts with manual operations
4. **Emergency Stop**: Administrative override capabilities
5. **Audit Logging**: Complete logging of automated scan activities

## User Experience Flow:

### Setup & Configuration
1. User accesses Scan Scheduler panel
2. Enables master toggle
3. Selects days of the week for scanning
4. Configures time windows (start/stop times)
5. Sets scan parameters and target networks
6. Saves configuration

### Automated Execution
1. Background service monitors schedule
2. When schedule conditions met, initiates scan
3. Shows progress indicators in UI
4. Generates reports automatically
5. Sends completion notifications

### Monitoring & Control
1. Real-time status display
2. Next scan time countdown
3. Manual override options
4. Historical scan results
5. Performance analytics

## Benefits:
1. **Consistent Monitoring**: Regular automated network assessment
2. **Operational Safety**: Scans only during approved time windows
3. **Resource Efficiency**: Scheduled execution prevents resource conflicts
4. **Compliance Support**: Regular scanning for security compliance
5. **Reduced Manual Effort**: Set-and-forget automation

## Acceptance Criteria:
1. ✅ Master toggle to enable/disable automated scanning
2. ✅ Day selection interface (include/exclude weekdays)
3. ✅ Time window configuration (start and stop times)
4. ✅ Automatic scan execution within defined schedules
5. ✅ Safety mechanisms (timeouts, resource limits)
6. ✅ Conflict prevention with manual operations
7. ✅ Progress indicators and status updates
8. ✅ Configuration persistence and validation
9. ✅ Notification system for scan results
10. ✅ Manual override and emergency stop capabilities

## Security Considerations:
- Validate scan targets to prevent unauthorized scanning
- Secure storage of schedule configurations
- Audit logging of all automated activities
- Access controls for schedule modification
- Network boundary awareness

## Technical Notes:
- Implement as background service thread
- Use system cron as fallback scheduling mechanism
- Handle system restarts and service recovery
- Provide REST API for external integration
- Support both SQLite and external database storage

---

## Implementation Priority:
1. **Phase 1**: Basic scheduling framework and UI
2. **Phase 2**: Time window logic and day selection
3. **Phase 3**: Automated execution and safety features
4. **Phase 4**: Advanced monitoring and analytics

This feature provides enterprise-grade automated scanning capabilities while maintaining operational safety and user control over timing and execution parameters.