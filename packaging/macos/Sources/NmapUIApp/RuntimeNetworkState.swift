import Darwin
import Foundation

struct RuntimeNetworkState: Codable, Equatable {
    let localIP: String
    let mask: String
    let cidr: String
    let publicIP: String
    let tracerouteHops: [RuntimeTracerouteHop]

    static func current() async -> RuntimeNetworkState {
        async let localInfo = localNetworkInfo()
        async let publicIP = publicIPAddress()
        async let tracerouteHops = tracerouteHops()
        let resolvedLocalInfo = await localInfo
        return RuntimeNetworkState(
            localIP: resolvedLocalInfo.localIP,
            mask: resolvedLocalInfo.mask,
            cidr: resolvedLocalInfo.cidr,
            publicIP: await publicIP,
            tracerouteHops: await tracerouteHops
        )
    }

    static func localNetworkInfo() -> (localIP: String, mask: String, cidr: String) {
        if let interfaceInfo = localInterfaceNetworkInfo() {
            return interfaceInfo
        }

        let routeOutput = runProcess("/usr/sbin/route", ["get", "default"], timeout: 2)
        let interface = firstCapture(in: routeOutput, pattern: #"interface:\s+([A-Za-z0-9_.-]+)"#) ?? "en0"
        let ifconfigOutput = runProcess("/sbin/ifconfig", [interface], timeout: 2)

        let ip = firstCapture(in: ifconfigOutput, pattern: #"inet\s+([0-9.]+)"#) ?? "Unknown"
        let maskHex = firstCapture(in: ifconfigOutput, pattern: #"netmask\s+0x([0-9a-fA-F]+)"#)
        let mask = maskHex.flatMap { hexMaskToInfo($0)?.dotted } ?? "Unknown"
        let cidr = maskHex.flatMap { getNetworkCidr(localIP: ip, maskHex: $0) } ?? "Unknown"
        return (ip, mask, cidr)
    }

    static func publicIPAddress() async -> String {
        guard let url = URL(string: "https://api.ipify.org?format=json") else {
            return "Unknown"
        }
        do {
            let session = URLSession(configuration: {
                let configuration = URLSessionConfiguration.ephemeral
                configuration.timeoutIntervalForRequest = 4
                configuration.timeoutIntervalForResource = 4
                return configuration
            }())
            let (data, response) = try await session.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                return "Unknown"
            }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json?["ip"] as? String ?? "Unknown"
        } catch {
            return "Unknown"
        }
    }

    static func tracerouteHops() async -> [RuntimeTracerouteHop] {
        let output = runProcess(
            "/usr/sbin/traceroute",
            ["-m", "15", "-n", "-q", "1", "8.8.8.8"],
            timeout: 6
        )

        let parsedHops: [RuntimeTracerouteHop] = output
            .split(separator: "\n")
            .compactMap { line -> RuntimeTracerouteHop? in
                let text = String(line)
                guard let hopValue = firstCapture(in: text, pattern: #"^\s*(\d+)\s+([0-9.]+)"#),
                      let hop = Int(hopValue),
                      let ip = firstCapture(in: text, pattern: #"^\s*(\d+)\s+([0-9.]+)"#, group: 2) else {
                    return nil
                }
                return RuntimeTracerouteHop(hop: hop, ip: ip)
            }
        if !parsedHops.isEmpty {
            return parsedHops
        }

        return defaultGatewayHop().map { [$0] } ?? []
    }

    private static func defaultGatewayHop() -> RuntimeTracerouteHop? {
        let routeOutput = runProcess("/usr/sbin/route", ["get", "default"], timeout: 2)
        guard let gateway = firstCapture(in: routeOutput, pattern: #"gateway:\s+([0-9.]+)"#) else {
            return nil
        }
        return RuntimeTracerouteHop(hop: 1, ip: gateway)
    }

    private static func localInterfaceNetworkInfo() -> (localIP: String, mask: String, cidr: String)? {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let firstInterface = interfaces else { return nil }
        defer { freeifaddrs(interfaces) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = firstInterface
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            let interface = current.pointee
            guard let address = interface.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET),
                  let netmask = interface.ifa_netmask else {
                continue
            }

            let flags = Int32(interface.ifa_flags)
            guard flags & IFF_UP != 0,
                  flags & IFF_RUNNING != 0,
                  flags & IFF_LOOPBACK == 0 else {
                continue
            }

            guard let ip = ipv4String(from: address),
                  !ip.hasPrefix("169.254."),
                  let mask = ipv4String(from: netmask),
                  let cidr = cidr(localIP: ip, dottedMask: mask) else {
                continue
            }

            return (ip, mask, cidr)
        }

        return nil
    }

    private static func ipv4String(from sockaddrPointer: UnsafePointer<sockaddr>) -> String? {
        var address = sockaddrPointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func cidr(localIP: String, dottedMask: String) -> String? {
        let ipParts = localIP.split(separator: ".").compactMap { UInt32($0) }
        let maskParts = dottedMask.split(separator: ".").compactMap { UInt32($0) }
        guard ipParts.count == 4, maskParts.count == 4 else { return nil }

        let ip = ipParts.reduce(0) { ($0 << 8) + $1 }
        let mask = maskParts.reduce(0) { ($0 << 8) + $1 }
        let network = ip & mask
        let octets = [
            String((network >> 24) & 0xff),
            String((network >> 16) & 0xff),
            String((network >> 8) & 0xff),
            String(network & 0xff)
        ]
        return "\(octets.joined(separator: "."))/\(mask.nonzeroBitCount)"
    }

    static func runProcess(_ executable: String, _ arguments: [String], timeout: TimeInterval = 10) -> String {
        guard let result = try? ExternalProcessRunner.run(
            executable: URL(fileURLWithPath: executable),
            arguments: arguments,
            timeout: timeout
        ) else {
            return ""
        }
        return result.stdout
    }

    static func firstCapture(in text: String, pattern: String, group: Int = 1) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.anchorsMatchLines]) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range),
              let captureRange = Range(match.range(at: group), in: text) else { return nil }
        return String(text[captureRange])
    }
}

struct RuntimeTracerouteHop: Codable, Equatable {
    let hop: Int
    let ip: String
}

private func hexMaskToInfo(_ maskHex: String) -> (dotted: String, maskInt: UInt32, prefix: Int)? {
    let normalized = maskHex
        .replacingOccurrences(of: "^0x", with: "", options: .regularExpression)
        .padding(toLength: 8, withPad: "0", startingAt: 0)
    guard let maskInt = UInt32(normalized, radix: 16) else { return nil }
    let octets = [
        String((maskInt >> 24) & 0xff),
        String((maskInt >> 16) & 0xff),
        String((maskInt >> 8) & 0xff),
        String(maskInt & 0xff)
    ]
    return (octets.joined(separator: "."), maskInt, maskInt.nonzeroBitCount)
}

func getNetworkCidr(localIP: String, maskHex: String) -> String? {
    let parts = localIP.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 4, let mask = hexMaskToInfo(maskHex) else { return nil }
    let ip = parts.reduce(0) { ($0 << 8) + $1 }
    let network = ip & mask.maskInt
    let octets = [
        String((network >> 24) & 0xff),
        String((network >> 16) & 0xff),
        String((network >> 8) & 0xff),
        String(network & 0xff)
    ]
    return "\(octets.joined(separator: "."))/\(mask.prefix)"
}
