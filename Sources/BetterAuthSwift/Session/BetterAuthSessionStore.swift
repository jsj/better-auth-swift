import Foundation
import os
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
            "Keychain operation failed with status \(status)."

        case .invalidData:
            "Stored session data was invalid."
        }
    }
}

/// Thread-safe in-memory session store.
public final class InMemorySessionStore: BetterAuthSessionStore, Sendable {
    private let storage = OSAllocatedUnfairLock(initialState: [String: BetterAuthSession]())

    public init() {}

    public func loadSession(for key: String) throws -> BetterAuthSession? {
        storage.withLock { $0[key] }
    }

    public func saveSession(_ session: BetterAuthSession, for key: String) throws {
        storage.withLock { $0[key] = session }
    }

    public func clearSession(for key: String) throws {
        _ = storage.withLock { $0.removeValue(forKey: key) }
    }
}

public struct MigratingSessionStore: BetterAuthSessionStore, Sendable {
    private let primary: any BetterAuthSessionStore
    private let legacyStores: [any BetterAuthSessionStore]
    private let removeLegacySessionOnMigration: Bool

    public init(primary: any BetterAuthSessionStore,
                legacyStores: [any BetterAuthSessionStore],
                removeLegacySessionOnMigration: Bool = true)
    {
        self.primary = primary
        self.legacyStores = legacyStores
        self.removeLegacySessionOnMigration = removeLegacySessionOnMigration
    }

    public func loadSession(for key: String) throws -> BetterAuthSession? {
        if let session = try primary.loadSession(for: key) {
            return session
        }

        for legacyStore in legacyStores {
            guard let session = try legacyStore.loadSession(for: key) else {
                continue
            }

            try primary.saveSession(session, for: key)
            if removeLegacySessionOnMigration {
                try legacyStore.clearSession(for: key)
            }
            return session
        }

        return nil
    }

    public func saveSession(_ session: BetterAuthSession, for key: String) throws {
        try primary.saveSession(session, for: key)
    }

    public func clearSession(for key: String) throws {
        try primary.clearSession(for: key)
        for legacyStore in legacyStores {
            try legacyStore.clearSession(for: key)
        }
    }
}

public struct KeychainSessionStore: BetterAuthSessionStore, Sendable {
    private static let missingEntitlementStatus = OSStatus(-34018)
    private static let memoryFallback = InMemorySessionStore()

    public enum Accessibility: Sendable, Equatable {
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

    public init(service: String,
                accessGroup: String? = nil,
                accessibility: Accessibility = .afterFirstUnlock,
                synchronizable: Bool = false)
    {
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

        case let status where Self.shouldUseMemoryFallback(for: status):
            return try Self.memoryFallback.loadSession(for: fallbackKey(for: key))

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
            if Self.shouldUseMemoryFallback(for: insertStatus) {
                try Self.memoryFallback.saveSession(session, for: fallbackKey(for: key))
                return
            }

            guard insertStatus == errSecSuccess else {
                throw BetterAuthSessionStoreError.unexpectedStatus(insertStatus)
            }

        case let status where Self.shouldUseMemoryFallback(for: status):
            try Self.memoryFallback.saveSession(session, for: fallbackKey(for: key))

        default:
            throw BetterAuthSessionStoreError.unexpectedStatus(status)
        }
    }

    public func clearSession(for key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        if Self.shouldUseMemoryFallback(for: status) {
            try Self.memoryFallback.clearSession(for: fallbackKey(for: key))
            return
        }

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw BetterAuthSessionStoreError.unexpectedStatus(status)
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: key]

        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        if synchronizable {
            query[kSecAttrSynchronizable as String] = true
        }

        return query
    }

    func fallbackKey(for key: String) -> String {
        [service, accessGroup, key].compactMap(\.self).joined(separator: ":")
    }

    static func shouldUseMemoryFallback(for status: OSStatus) -> Bool {
        #if targetEnvironment(simulator)
            status == missingEntitlementStatus
        #else
            false
        #endif
    }
}
