import Foundation
import CryptoKit

private enum HelperError: Error {
    case invalidCommand
    case invalidPayload(String)
}

private struct TokenState: Codable {
    var schemaVersion: Int = 1
    var ciphertext: String?
    var refreshToken: String?
    var accessToken: String?
    var expiresAt: String?
    var pendingAuth: PendingAuth?
}

private struct Credentials: Codable {
    var clientId: String?
    var clientSecret: String?
}

private struct PendingAuth: Codable {
    var state: String
    var codeVerifier: String
    var redirectUri: String
    var createdAt: String
}

private struct HelperResponse: Codable {
    var success: Bool
    var status: String?
    var error: String?
    var configured: Bool?
    var connected: Bool?
    var expiresAt: String?
    var authURL: String?
}

private func readJSON<T: Decodable>(_ type: T.Type, from path: URL) -> T? {
    guard let data = try? Data(contentsOf: path) else { return nil }
    return try? JSONDecoder().decode(T.self, from: data)
}

private func writeJSON<T: Encodable>(_ value: T, to path: URL) throws {
    let data = try JSONEncoder().encode(value)
    try data.write(to: path, options: [.atomic])
}

private func defaultPaths(root: URL) -> (credentials: URL, token: URL, key: URL) {
    let state = root.appendingPathComponent(".google_drive", isDirectory: true)
    return (
        state.appendingPathComponent("credentials.json"),
        state.appendingPathComponent("token.json"),
        state.appendingPathComponent("token.key")
    )
}

private func printJSON(_ value: HelperResponse) {
    if let data = try? JSONEncoder().encode(value),
       let jsonObject = try? JSONSerialization.jsonObject(with: data),
       let pretty = try? JSONSerialization.data(withJSONObject: jsonObject, options: [.prettyPrinted]),
       let string = String(data: pretty, encoding: .utf8) {
        print(string)
    } else {
        print("{}")
    }
}

private func randomURLSafeToken(byteCount: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func sha256URLSafe(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return Data(digest).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private struct SimpleResponse {
    let statusCode: Int
    let body: Data
}

private func postForm(url: URL, body: [String: String]) throws -> SimpleResponse {
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = body
        .map { "\($0.key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
        .joined(separator: "&")
        .data(using: .utf8)

    let semaphore = DispatchSemaphore(value: 0)
    var output: SimpleResponse?
    var caught: Error?

    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()

    semaphore.wait()
    if let caught { throw caught }
    guard let output else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func jsonObject(from data: Data) -> [String: Any] {
    (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
}

private func percentEncode(_ value: String) -> String {
    value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

private func makeMultipartBody(metadata: [String: Any], fileName: String, fileData: Data) -> (body: Data, boundary: String) {
    let boundary = "----nmapui-\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
    var body = Data()
    func append(_ string: String) { body.append(Data(string.utf8)) }

    append("--\(boundary)\r\n")
    append("Content-Disposition: form-data; name=\"metadata\"; filename=\"metadata.json\"\r\n")
    append("Content-Type: application/json; charset=UTF-8\r\n\r\n")
    body.append((try? JSONSerialization.data(withJSONObject: metadata)) ?? Data())
    append("\r\n")

    append("--\(boundary)\r\n")
    append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
    append("Content-Type: application/octet-stream\r\n\r\n")
    body.append(fileData)
    append("\r\n")

    append("--\(boundary)--\r\n")
    return (body, boundary)
}

private func formURLEncoded(_ fields: [String: String]) -> Data {
    fields
        .map { "\(percentEncode($0.key))=\(percentEncode($0.value))" }
        .joined(separator: "&")
        .data(using: .utf8) ?? Data()
}

private func httpGET(url: String, query: [String: String]? = nil, headers: [String: String] = [:]) throws -> SimpleResponse {
    var components = URLComponents(string: url)!
    if let query {
        components.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
    }
    var request = URLRequest(url: components.url!)
    request.httpMethod = "GET"
    headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
    let semaphore = DispatchSemaphore(value: 0)
    var output: SimpleResponse?
    var caught: Error?
    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()
    semaphore.wait()
    if let caught { throw caught }
    guard let output else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func httpPOST(
    url: String,
    headers: [String: String] = [:],
    body: Data = Data()
) throws -> SimpleResponse {
    var request = URLRequest(url: URL(string: url)!)
    request.httpMethod = "POST"
    headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
    request.httpBody = body
    let semaphore = DispatchSemaphore(value: 0)
    var output: SimpleResponse?
    var caught: Error?
    URLSession.shared.dataTask(with: request) { data, response, error in
        defer { semaphore.signal() }
        if let error {
            caught = error
            return
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            caught = HelperError.invalidPayload("Missing HTTP response")
            return
        }
        output = SimpleResponse(statusCode: httpResponse.statusCode, body: data ?? Data())
    }.resume()
    semaphore.wait()
    if let caught { throw caught }
    guard let output else { throw HelperError.invalidPayload("Missing response body") }
    return output
}

private func ensureAccessToken(paths: (credentials: URL, token: URL, key: URL)) throws -> String {
    guard let tokenState = readJSON(TokenState.self, from: paths.token) else {
        throw HelperError.invalidPayload("Google Drive is not connected.")
    }
    if let accessToken = tokenState.accessToken, !accessToken.isEmpty {
        return accessToken
    }
    if let refreshToken = tokenState.refreshToken, !refreshToken.isEmpty {
        let credentials = readJSON([String: String].self, from: paths.credentials) ?? [:]
        guard let clientId = credentials["client_id"], let clientSecret = credentials["client_secret"] else {
            throw HelperError.invalidPayload("Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.")
        }
        let response = try httpPOST(url: "https://oauth2.googleapis.com/token", headers: ["Content-Type": "application/x-www-form-urlencoded"], body: formURLEncoded([
            "client_id": clientId,
            "client_secret": clientSecret,
            "refresh_token": refreshToken,
            "grant_type": "refresh_token",
        ]))
        let payload = jsonObject(from: response.body)
        guard response.statusCode < 400, let refreshed = payload["access_token"] as? String else {
            throw HelperError.invalidPayload((payload["error_description"] as? String) ?? (payload["error"] as? String) ?? "Failed to refresh Google Drive access token.")
        }
        var updated = tokenState
        updated.accessToken = refreshed
        updated.expiresAt = ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval((payload["expires_in"] as? Double).map { Int($0) } ?? 3600)))
        try writeJSON(updated, to: paths.token)
        return refreshed
    }
    throw HelperError.invalidPayload("Google Drive is not connected.")
}

private func ensureReportsFolder(
    paths: (credentials: URL, token: URL, key: URL),
    folderName: String,
    parentID: String?
) throws -> String {
    let accessToken = try ensureAccessToken(paths: paths)
    let escaped = folderName.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "'", with: "\\'")
    var query = "mimeType='application/vnd.google-apps.folder' and name='\(escaped)' and trashed=false"
    if let parentID {
        query += " and '\(parentID)' in parents"
    }
    let list = try httpGET(url: "https://www.googleapis.com/drive/v3/files", query: ["q": query, "fields": "files(id,name,webViewLink)"], headers: ["Authorization": "Bearer \(accessToken)"])
    let listPayload = jsonObject(from: list.body)
    if let files = listPayload["files"] as? [[String: Any]], let first = files.first, let id = first["id"] as? String {
        return id
    }
    var folderPayload: [String: Any] = ["name": folderName, "mimeType": "application/vnd.google-apps.folder"]
    if let parentID { folderPayload["parents"] = [parentID] }
    let body = (try? JSONSerialization.data(withJSONObject: folderPayload)) ?? Data()
    let create = try httpPOST(
        url: "https://www.googleapis.com/drive/v3/files",
        headers: [
            "Authorization": "Bearer \(accessToken)",
            "Content-Type": "application/json",
        ],
        body: body
    )
    let createPayload = jsonObject(from: create.body)
    if let id = createPayload["id"] as? String {
        return id
    }
    throw HelperError.invalidPayload("Failed to create Drive folder.")
}

private func uploadFile(
    path: URL,
    folderID: String,
    fileNameMap: [String: String],
    paths: (credentials: URL, token: URL, key: URL)
) throws -> [String: Any] {
    let accessToken = try ensureAccessToken(paths: paths)
    let overrideName = fileNameMap[path.path]
    let metadata: [String: Any] = {
        var value: [String: Any] = ["name": overrideName ?? path.lastPathComponent]
        if !folderID.isEmpty { value["parents"] = [folderID] }
        return value
    }()
    let fileData = try Data(contentsOf: path)
    let (multipartBody, boundary) = makeMultipartBody(metadata: metadata, fileName: path.lastPathComponent, fileData: fileData)
    let response = try httpPOST(
        url: "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink",
        headers: [
            "Authorization": "Bearer \(accessToken)",
            "Content-Type": "multipart/form-data; boundary=\(boundary)",
        ],
        body: multipartBody
    )
    let payload = jsonObject(from: response.body)
    if response.statusCode >= 400 {
        throw HelperError.invalidPayload((payload["error"] as? [String: Any])?["message"] as? String ?? "Drive upload failed.")
    }
    return payload
}

@main
struct GoogleDriveHelper {
    static func main() {
        var args = CommandLine.arguments.dropFirst()
        guard let command = args.first else {
            printJSON(HelperResponse(success: false, status: nil, error: "Missing command", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
            exit(1)
        }
        args = args.dropFirst()

        var root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        var redirectURI = ""
        var credentialsJSON = ""
        var code = ""
        var state = ""

        var i = 0
        while i < args.count {
            let arg = args[args.index(args.startIndex, offsetBy: i)]
            switch arg {
            case "--root":
                i += 1
                root = URL(fileURLWithPath: String(args[args.index(args.startIndex, offsetBy: i)]))
            case "--redirect-uri":
                i += 1
                redirectURI = String(args[args.index(args.startIndex, offsetBy: i)])
            case "--credentials-json":
                i += 1
                credentialsJSON = String(args[args.index(args.startIndex, offsetBy: i)])
            case "--code":
                i += 1
                code = String(args[args.index(args.startIndex, offsetBy: i)])
            case "--state":
                i += 1
                state = String(args[args.index(args.startIndex, offsetBy: i)])
            default:
                break
            }
            i += 1
        }

        let paths = defaultPaths(root: root)

        do {
            switch command {
            case "status":
                let credentials = readJSON([String: String].self, from: paths.credentials) ?? [:]
                let tokenState = readJSON(TokenState.self, from: paths.token)
                let configured = (credentials["client_id"]?.isEmpty == false) && (credentials["client_secret"]?.isEmpty == false)
                let connected = (tokenState?.refreshToken?.isEmpty == false) || (tokenState?.accessToken?.isEmpty == false)
                let status: String = connected ? "Connected" : (configured ? "Not connected" : "OAuth credentials missing. Import credentials.json to enable Google Drive.")
                printJSON(HelperResponse(success: true, status: status, error: nil, configured: configured, connected: connected, expiresAt: tokenState?.expiresAt, authURL: nil))
                exit(0)

            case "save-credentials":
                let payloadData = credentialsJSON.isEmpty ? Data("{}".utf8) : Data(credentialsJSON.utf8)
                guard let _ = try? JSONSerialization.jsonObject(with: payloadData) else {
                    throw HelperError.invalidPayload("Invalid credentials payload")
                }
                try FileManager.default.createDirectory(at: paths.credentials.deletingLastPathComponent(), withIntermediateDirectories: true)
                try payloadData.write(to: paths.credentials, options: [.atomic])
                printJSON(HelperResponse(success: true, status: "Google Drive credentials saved", error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                exit(0)

            case "auth-url":
                let credentials = readJSON([String: String].self, from: paths.credentials) ?? [:]
                guard let clientId = credentials["client_id"], !clientId.isEmpty,
                      let _ = credentials["client_secret"], !redirectURI.isEmpty else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let stateToken = randomURLSafeToken(byteCount: 24)
                let verifier = randomURLSafeToken(byteCount: 48)
                let challenge = sha256URLSafe(verifier)
                let pending = PendingAuth(state: stateToken, codeVerifier: verifier, redirectUri: redirectURI, createdAt: ISO8601DateFormatter().string(from: Date()))
                try writeJSON(TokenState(schemaVersion: 1, ciphertext: nil, refreshToken: nil, accessToken: nil, expiresAt: nil, pendingAuth: pending), to: paths.token)
                let authURL = "https://accounts.google.com/o/oauth2/v2/auth?client_id=\(clientId)&redirect_uri=\(redirectURI)&response_type=code&scope=https://www.googleapis.com/auth/drive.file&access_type=offline&prompt=consent&include_granted_scopes=true&state=\(stateToken)&code_challenge=\(challenge)&code_challenge_method=S256"
                printJSON(HelperResponse(success: true, status: nil, error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: authURL))
                exit(0)

            case "disconnect":
                try? FileManager.default.removeItem(at: paths.token)
                try? FileManager.default.removeItem(at: paths.key)
                printJSON(HelperResponse(success: true, status: "Google Drive disconnected", error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                exit(0)

            case "exchange-code":
                let tokenState = readJSON(TokenState.self, from: paths.token)
                guard let pending = tokenState?.pendingAuth else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Invalid or expired Google Drive auth state.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                guard pending.state == state else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Invalid or expired Google Drive auth state.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let credentials = readJSON([String: String].self, from: paths.credentials) ?? [:]
                guard let clientId = credentials["client_id"], let clientSecret = credentials["client_secret"] else {
                    printJSON(HelperResponse(success: false, status: nil, error: "Google Drive OAuth credentials file not found. Upload your credentials.json from the Google Cloud Console.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let response = try postForm(url: URL(string: "https://oauth2.googleapis.com/token")!, body: [
                    "client_id": clientId,
                    "client_secret": clientSecret,
                    "code": code,
                    "code_verifier": pending.codeVerifier,
                    "grant_type": "authorization_code",
                    "redirect_uri": pending.redirectUri,
                ])
                let payload = jsonObject(from: response.body)
                if response.statusCode >= 400 || payload["access_token"] == nil {
                    printJSON(HelperResponse(success: false, status: nil, error: (payload["error_description"] as? String) ?? (payload["error"] as? String) ?? "Failed to exchange Google Drive auth code.", configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                    exit(1)
                }
                let expiresIn = (payload["expires_in"] as? Double).map { Int($0) } ?? 3600
                var updatedState = TokenState(schemaVersion: 1, ciphertext: nil, refreshToken: tokenState?.refreshToken ?? (payload["refresh_token"] as? String), accessToken: payload["access_token"] as? String, expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(TimeInterval(expiresIn))), pendingAuth: nil)
                try writeJSON(updatedState, to: paths.token)
                printJSON(HelperResponse(success: true, status: "Google Drive connected", error: nil, configured: nil, connected: nil, expiresAt: updatedState.expiresAt, authURL: nil))
                exit(0)

            case "upload":
                let filePaths = args
                    .filter { $0.hasPrefix("/") }
                    .map { URL(fileURLWithPath: $0) }
                let folderName = "Nmap Reports"
                let folderID = try ensureReportsFolder(paths: paths, folderName: folderName, parentID: nil)
                var uploaded: [[String: Any]] = []
                for fileURL in filePaths {
                    let result = try uploadFile(path: fileURL, folderID: folderID, fileNameMap: [:], paths: paths)
                    uploaded.append(result)
                }
                printJSON(HelperResponse(success: true, status: "Uploaded \(uploaded.count) file(s) to Google Drive", error: nil, configured: nil, connected: nil, expiresAt: nil, authURL: nil))
                exit(0)

            default:
                throw HelperError.invalidCommand
            }
        } catch {
            printJSON(HelperResponse(success: false, status: nil, error: String(describing: error), configured: nil, connected: nil, expiresAt: nil, authURL: nil))
            exit(1)
        }
    }
}
