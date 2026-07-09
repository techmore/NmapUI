import Foundation

enum RuntimeReportNaming {
    static func sanitizeSegment(_ value: String?, fallback: String = "unknown") -> String {
        let cleaned = String(value ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: #"[^0-9A-Za-z_.-]+"#, with: "_", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return cleaned.isEmpty ? fallback : cleaned
    }

    static func formatTimestamp(_ date: Date = Date()) -> String {
        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(in: TimeZone(secondsFromGMT: 0) ?? .current, from: date)
        func pad(_ value: Int?) -> String { String(format: "%02d", value ?? 0) }
        return "\(components.year ?? 0)_\(pad(components.month))_\(pad(components.day))_\(pad(components.hour))\(pad(components.minute))\(pad(components.second))"
    }

    static func formatDisplayTimestamp(_ date: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "MMM dd, yyyy, HH:mm:ss zzz"
        formatter.timeZone = TimeZone.current
        return formatter.string(from: date)
    }

    static func formatDriveDayFolder(_ date: Date = Date()) -> String {
        let calendar = Calendar(identifier: .gregorian)
        let components = calendar.dateComponents(in: TimeZone.current, from: date)
        func pad(_ value: Int?) -> String { String(format: "%02d", value ?? 0) }
        return "\(components.year ?? 0)-\(pad(components.month))-\(pad(components.day))"
    }
}
