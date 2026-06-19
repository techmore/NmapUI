import Foundation

enum RuntimeEndpoints {
    static let host = "127.0.0.1"
    static let port = 9000

    static var baseURL: URL {
        URL(string: "http://\(host):\(port)")!
    }

    static var readinessURL: URL {
        baseURL.appendingPathComponent("api/health/ready")
    }

    static var fixedPortString: String {
        String(port)
    }
}
