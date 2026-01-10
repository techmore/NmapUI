# GitHub Issue: Feature Request - Clock Updates Precisely on the Minute

## Title: Feature: Clock Updates Precisely on the Minute in Header

## Summary:
- Modify the header clock to update precisely at :00 seconds (top of each minute)
- Calculate initial delay to sync with minute boundaries
- Maintain accurate time display that aligns with system clock minutes

## Problem Statement:
The current header clock updates every 60 seconds from page load, but doesn't align with actual minute boundaries. This means the displayed time may show 10:15:45 when the actual time is 10:16:02, creating confusion for users who expect the clock to show the current minute accurately.

The clock should update precisely when the minute changes (at :00 seconds) to provide accurate time display that users can rely on.

## Proposed Solution:

### 1. Precise Minute Synchronization
- Calculate the milliseconds until the next minute boundary on page load
- Set initial timeout to sync with :00 seconds
- Subsequent updates occur every 60 seconds thereafter

### 2. Accurate Time Display
- Clock shows current minute accurately throughout the minute
- No drift from actual time boundaries
- Consistent with system clock minute changes

### 3. Implementation Details
Replace the current simple `setInterval(updateDateTime, 60000)` with a more precise timing mechanism that calculates the initial delay.

## Implementation Details:

### Frontend Changes (templates/index.html)
1. **Enhanced Clock Update Logic**
   ```javascript
   function updateDateTime() {
       const now = new Date();
       const options = {
           weekday: 'long',
           year: 'numeric',
           month: 'long',
           day: 'numeric',
           hour: '2-digit',
           minute: '2-digit'
       };
       document.getElementById('current-date-time').textContent =
           now.toLocaleDateString('en-US', options);
   }

   function scheduleNextUpdate() {
       const now = new Date();
       const seconds = now.getSeconds();
       const milliseconds = now.getMilliseconds();

       // Calculate milliseconds until next minute boundary (:00 seconds)
       const millisecondsUntilNextMinute = (60 - seconds) * 1000 - milliseconds;

       // Schedule the next update
       setTimeout(() => {
           updateDateTime();
           // Set up regular updates every 60 seconds thereafter
           setInterval(updateDateTime, 60000);
       }, millisecondsUntilNextMinute);
   }

   // Initialize clock
   updateDateTime();
   scheduleNextUpdate();
   ```

### Alternative Implementation (More Robust)
```javascript
function startPreciseClock() {
    function updateClock() {
        updateDateTime();
    }

    // Update immediately
    updateClock();

    // Calculate time to next minute
    const now = new Date();
    const secondsUntilNextMinute = 60 - now.getSeconds();
    const msUntilNextMinute = secondsUntilNextMinute * 1000 - now.getMilliseconds();

    // Schedule first update at minute boundary
    setTimeout(() => {
        updateClock();
        // Then update every minute thereafter
        setInterval(updateClock, 60000);
    }, msUntilNextMinute);
}

// Start the precise clock
startPreciseClock();
```

## User Experience Flow:

### Page Load
1. Page loads and clock displays current time immediately
2. System calculates milliseconds until next minute boundary
3. Clock updates precisely at :00 seconds
4. Subsequent updates occur every 60 seconds thereafter

### Continuous Operation
1. Clock always shows accurate current minute
2. Updates align perfectly with system clock minute changes
3. No visible lag or drift from actual time

## Benefits:
1. **Accuracy**: Clock displays current minute precisely
2. **Reliability**: Users can trust the displayed time
3. **Professional**: Consistent with standard clock behavior
4. **User Trust**: Eliminates confusion about displayed time

## Acceptance Criteria:
1. ✅ Clock updates precisely at :00 seconds (minute boundary)
2. ✅ Initial update is scheduled to align with next minute
3. ✅ Subsequent updates occur every 60 seconds
4. ✅ Displayed time accurately reflects current minute throughout
5. ✅ No drift from system clock minute changes
6. ✅ Works correctly across page refreshes and browser restarts

## Technical Notes:
- Uses `setTimeout` for initial alignment, `setInterval` for ongoing updates
- Calculates precise timing based on current seconds and milliseconds
- Handles edge cases like page load at :59 seconds
- Maintains existing time format and styling
- No changes to server-side time handling

## Testing Scenarios:
- Page load at :00 seconds (immediate update, then every minute)
- Page load at :30 seconds (update in 30 seconds, then every minute)
- Page load at :59 seconds (update in 1 second, then every minute)
- Browser tab inactive/background (maintains accuracy when reactivated)
- System time changes (handles gracefully)

---

## Implementation Priority: Low
This is a small but important UX improvement that enhances perceived accuracy and professionalism of the application.

## Related Files:
- `templates/index.html` (JavaScript clock update logic)

The fix is straightforward but provides significant value in terms of user trust and professional appearance.