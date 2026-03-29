import Foundation
import Security

public protocol BetterAuthSessionStore: Sendable {
    func loadSession(for key: String) throws -> BetterAuthSession?
    func saveSession(_ session: BetterAuthSession, for key: String) throws
    func clearSession(for key: String) throws
}

public enum BetterAuthSessionStoreError: LocalizedError, Sendable {
    case unexpectedStatus(OSStatus)
    case invalidData

    public var errorDescription: String? {
        switch self {
        case let .unexpectedStatus(status):
            return "Keychain operation failed with status \(status)."
        case .invalidData:
            return "Stored session data was invalid."
        }
    }
}

public final class InMemorySessionStore: BetterAuthSessionStore, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: BetterAuthSession] = [:]

    public init() {}

    public func loadSession(for key: String) throws -> BetterAuthSession? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    public func saveSession(_ session: BetterAuthSession, for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = session
    }

    public func clearSession(for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: key)
    }
}

public struct KeychainSessionStore: BetterAuthSessionStore, Sendable {
    public enum Accessibility: Sendable {
        case afterFirstUnlock
        case afterFirstUnlockThisDeviceOnly
        case whenUnlocked
        case whenUnlockedThisDeviceOnly

        fileprivate var value: CFString {
            switch self {
            case .afterFirstUnlock:
                kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenUnlocked:
                kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            }
        }
    }

    public let service: String
    public let accessGroup: String?
    public let accessibility: Accessibility
    public let synchronizable: Bool

    public init(
        service: String,
        accessGroup: String? = nil,
        accessibility: Accessibility = .afterFirstUnlock,
        synchronizable: Bool = false
    ) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessibility = accessibility
        self.synchronizable = synchronizable
    }

    public func loadSession(for key: String) throws -> BetterAuthSession? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else {
                throw BetterAuthSessionStoreError.invalidData
            }
            return try BetterAuthCoding.makeDecoder().decode(BetterAuthSession.self, from: data)
        case errSecItemNotFound:
            return nil
        default:
            throw BetterAuthSessionStoreError.unexpectedStatus(status)
        }
    }

    public func saveSession(_ session: BetterAuthSession, for key: String) throws {
        let data = try BetterAuthCoding.makeEncoder().encode(session)
        let query = baseQuery(for: key)
        let attributes = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)

        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var insertQuery = query
            insertQuery[kSecValueData as String] = data
            insertQuery[kSecAttrAccessible as String] = accessibility.value
            let insertStatus = SecItemAdd(insertQuery as CFDictionary, nil)
            guard insertStatus == errSecSuccess else {
                throw BetterAuthSessionStoreError.unexpectedStatus(insertStatus)
            }
        default:
            throw BetterAuthSessionStoreError.unexpectedStatus(status)
        }
    }

    public func clearSession(for key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BetterAuthSessionStoreError.unexpectedStatus(status)
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]

        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        if synchronizable {
            query[kSecAttrSynchronizable as String] = true
        }

        return query
    }
}
