# GitHub Issue: Feature Request - Idle Auto-Update Banner with Countdown

## Title: Feature: Idle Auto-Update Banner with Countdown Timer

## Summary:
- Detect when the application is idle (no active scans or report generation)
- Display an auto-update banner with 30-second countdown
- Automatically trigger update when countdown completes
- Allow user to dismiss or manually trigger update

## Problem Statement:
Currently, application updates require manual initiation through the Update Center. Users may forget to update the application, leading to running outdated versions with potential security vulnerabilities or missing features. The update process should be more proactive while respecting user workflow by only triggering when the system is not actively scanning or generating reports.

## Proposed Solution:

### 1. Idle State Detection
- Monitor application state for active operations:
  - Quick scan in progress
  - Deep scan in progress
  - Report generation active
  - File transfers/sync operations
- Define "idle" state as no active operations for configurable time (default: 30 seconds)

### 2. Auto-Update Banner
- Display prominent banner when update available and system is idle
- Show update details (version, release notes summary)
- Include 30-second countdown with visual progress indicator
- Provide clear action buttons (Update Now, Remind Later, Dismiss)

### 3. Countdown & Auto-Update
- Visual countdown timer with progress bar
- Automatic update execution when timer reaches zero
- Graceful handling of user interactions during countdown
- Pause/resume countdown based on user activity

### 4. User Control Options
- **Update Now**: Immediate update trigger
- **Remind Later**: Dismiss for current session
- **Snooze**: Hide for configurable time period
- **Disable Auto-Updates**: Permanent opt-out option

## Implementation Details:

### Backend Changes (app.py)
1. **Idle State Manager**
   ```python
   class IdleStateManager:
       def __init__(self):
           self.active_operations = set()
           self.last_activity = datetime.now()
           self.idle_threshold = 30  # seconds

       def start_operation(self, operation_id):
           self.active_operations.add(operation_id)
           self.last_activity = datetime.now()

       def end_operation(self, operation_id):
           self.active_operations.discard(operation_id)

       def is_idle(self):
           return (len(self.active_operations) == 0 and
                   (datetime.now() - self.last_activity).seconds >= self.idle_threshold)
   ```

2. **Update Service Integration**
   - Integrate with existing update checking mechanism
   - Add auto-update scheduling logic
   - Track update availability and user preferences

3. **New Socket Events**
   - `idle_state_changed` - Notify UI of idle/active state changes
   - `update_available` - Send update details when detected
   - `auto_update_starting` - Signal impending auto-update
   - `auto_update_progress` - Show update progress during countdown
   - `auto_update_cancelled` - Handle user cancellation

### Frontend Changes (templates/index.html)
1. **Auto-Update Banner Component**
   ```html
   <div id="auto-update-banner" class="hidden fixed top-0 left-0 right-0 z-50 bg-gradient-to-r from-olive-600 to-olive-700 text-white p-4 shadow-lg">
       <div class="flex items-center justify-between">
           <div class="flex items-center space-x-4">
               <div class="flex-shrink-0">
                   <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                       <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.293l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L9 9.414V13a1 1 0 102 0V9.414l1.293 1.293a1 1 0 001.414-1.414z" clip-rule="evenodd"/>
                   </svg>
               </div>
               <div>
                   <h3 class="text-lg font-semibold">Update Available!</h3>
                   <p class="text-olive-100">NmapUI v2026.1.9.13_45 is ready to install</p>
               </div>
           </div>
           <div class="flex items-center space-x-4">
               <div id="countdown-timer" class="text-2xl font-mono font-bold">
                   30
               </div>
               <div class="flex space-x-2">
                   <button id="update-now-btn" class="bg-white text-olive-700 px-4 py-2 rounded-lg font-medium hover:bg-olive-50 transition-colors">
                       Update Now
                   </button>
                   <button id="remind-later-btn" class="bg-olive-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-olive-400 transition-colors">
                       Remind Later
                   </button>
               </div>
           </div>
       </div>
       <div class="mt-3">
           <div class="bg-olive-500 rounded-full h-2">
               <div id="progress-bar" class="bg-white h-2 rounded-full transition-all duration-1000" style="width: 100%"></div>
           </div>
       </div>
   </div>
   ```

2. **Countdown Logic**
   ```javascript
   class AutoUpdateBanner {
       constructor() {
           this.countdownInterval = null;
           this.remainingSeconds = 30;
           this.isVisible = false;
       }

       show(updateInfo) {
           this.remainingSeconds = 30;
           this.isVisible = true;
           this.startCountdown();
           // Show banner with animation
       }

       startCountdown() {
           this.countdownInterval = setInterval(() => {
               this.remainingSeconds--;
               this.updateDisplay();

               if (this.remainingSeconds <= 0) {
                   this.performAutoUpdate();
               }
           }, 1000);
       }

       updateDisplay() {
           const progressPercent = (this.remainingSeconds / 30) * 100;
           document.getElementById('countdown-timer').textContent = this.remainingSeconds;
           document.getElementById('progress-bar').style.width = `${progressPercent}%`;
       }

       performAutoUpdate() {
           clearInterval(this.countdownInterval);
           socket.emit('trigger_update');
           // Show update in progress indicator
       }
   }
   ```

3. **User Interaction Handlers**
   - Handle "Update Now" immediate trigger
   - Handle "Remind Later" dismissal with timer
   - Handle banner dismissal gestures
   - Respect user preferences for auto-update behavior

### Configuration Options
- **Idle Detection**
  - Idle threshold time (default: 30 seconds)
  - Operations to monitor (scans, reports, transfers)

- **Update Behavior**
  - Auto-update enabled/disabled
  - Countdown duration (10-60 seconds)
  - Update frequency (always, major only, security only)

- **User Preferences**
  - Auto-update during business hours only
  - Require manual confirmation for major updates
  - Snooze duration for "Remind Later" (1 hour, 1 day, 1 week)

### State Management
- Track application busy/idle state
- Monitor update availability
- Store user preferences in local storage
- Handle interrupted update flows

## User Experience Flow:

### Idle State Detection
1. System continuously monitors for active operations
2. When no operations active for 30+ seconds, enters "idle" state
3. If update available, show auto-update banner

### Countdown Experience
1. Banner appears with 30-second countdown
2. Visual progress bar shows time remaining
3. Large countdown number for clear visibility
4. User can interact at any time

### Auto-Update Process
1. When countdown reaches zero, automatically start update
2. Show update progress in banner
3. Handle update completion or failure
4. Offer restart if needed

### User Control Scenarios
- **Immediate Update**: Click "Update Now" for instant trigger
- **Delayed Update**: Click "Remind Later" to snooze banner
- **Disable Feature**: Option to permanently disable auto-updates
- **Manual Override**: Cancel countdown and continue working

## Benefits:
1. **Proactive Updates**: Automatic update notifications without disrupting workflow
2. **User Control**: Multiple options for update timing and preferences
3. **Safety**: Only triggers when system is idle and safe to update
4. **Visibility**: Clear countdown and progress indicators
5. **Flexibility**: Configurable behavior to match user preferences

## Acceptance Criteria:
1. ✅ Detect idle state when no scans or reports are running
2. ✅ Show update banner only during idle periods
3. ✅ Display 30-second countdown with progress indicator
4. ✅ Allow user to trigger immediate update
5. ✅ Allow user to dismiss/snooze banner
6. ✅ Automatically trigger update when countdown completes
7. ✅ Handle update failures gracefully
8. ✅ Respect user preferences and configuration
9. ✅ Provide clear visual feedback throughout process
10. ✅ Support both automatic and manual update modes

## Security Considerations:
- Validate update source integrity
- Ensure no sensitive operations interrupted
- Provide rollback capability if update fails
- Audit logging of update events
- User consent for automatic updates

## Technical Notes:
- Integrate with existing update mechanism
- Use WebSocket for real-time state updates
- Implement as non-blocking background process
- Handle network interruptions during updates
- Provide fallback to manual update if auto-update fails

---

## Implementation Priority:
1. **Phase 1**: Basic idle detection and banner display
2. **Phase 2**: Countdown timer and auto-update logic
3. **Phase 3**: User preferences and configuration
4. **Phase 4**: Advanced features (scheduling, rollback)

This feature enhances the user experience by making updates more proactive while ensuring they never interrupt critical scanning or reporting operations.