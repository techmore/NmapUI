import Foundation

enum AutoScanSchedule {
    /// Computes the next scheduled fire date for the given auto-scan settings.
    static func nextRunDate(
        enabled: Bool,
        recurrence: String,
        startTime: String,
        now: Date = Date(),
        calendar: Calendar = .current
    ) -> Date? {
        guard enabled else { return nil }

        let parts = startTime.split(separator: ":")
        let hour = parts.count > 0 ? Int(parts[0]) ?? 1 : 1
        let minute = parts.count > 1 ? Int(parts[1]) ?? 0 : 0
        let clampedHour = min(max(hour, 0), 23)
        let clampedMinute = min(max(minute, 0), 59)

        switch recurrence {
        case "hourly":
            var components = calendar.dateComponents([.year, .month, .day, .hour], from: now)
            components.minute = clampedMinute
            components.second = 0
            if let candidate = calendar.date(from: components), candidate > now {
                return candidate
            }
            return calendar.date(byAdding: .hour, value: 1, to: calendar.date(from: components) ?? now)

        case "weekly":
            // Match LaunchAgent: Monday at the chosen time (Calendar weekday 2 = Monday).
            return nextWeekday(2, hour: clampedHour, minute: clampedMinute, after: now, calendar: calendar)

        case "monthly":
            var components = calendar.dateComponents([.year, .month], from: now)
            components.day = 1
            components.hour = clampedHour
            components.minute = clampedMinute
            components.second = 0
            if let thisMonth = calendar.date(from: components), thisMonth > now {
                return thisMonth
            }
            guard let nextMonth = calendar.date(byAdding: .month, value: 1, to: calendar.date(from: components) ?? now) else {
                return nil
            }
            var nextComponents = calendar.dateComponents([.year, .month], from: nextMonth)
            nextComponents.day = 1
            nextComponents.hour = clampedHour
            nextComponents.minute = clampedMinute
            nextComponents.second = 0
            return calendar.date(from: nextComponents)

        default: // daily
            var components = calendar.dateComponents([.year, .month, .day], from: now)
            components.hour = clampedHour
            components.minute = clampedMinute
            components.second = 0
            if let today = calendar.date(from: components), today > now {
                return today
            }
            return calendar.date(byAdding: .day, value: 1, to: calendar.date(from: components) ?? now)
        }
    }

    static func formattedNextRun(_ date: Date?) -> String? {
        guard let date else { return nil }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private static func nextWeekday(
        _ weekday: Int,
        hour: Int,
        minute: Int,
        after now: Date,
        calendar: Calendar
    ) -> Date? {
        // weekday: 1=Sunday ... 7=Saturday
        for offset in 0..<8 {
            guard let day = calendar.date(byAdding: .day, value: offset, to: now) else { continue }
            let dayWeekday = calendar.component(.weekday, from: day)
            guard dayWeekday == weekday else { continue }
            var components = calendar.dateComponents([.year, .month, .day], from: day)
            components.hour = hour
            components.minute = minute
            components.second = 0
            if let candidate = calendar.date(from: components), candidate > now {
                return candidate
            }
        }
        return nil
    }
}
