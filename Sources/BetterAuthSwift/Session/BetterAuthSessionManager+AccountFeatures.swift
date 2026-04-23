import Foundation

public extension BetterAuthSessionManager {
    // MARK: - JWT

    func getSessionJWT() async throws -> BetterAuthJWT {
        try await makeSessionAdministrationService()
            .getSessionJWT(accessToken: state.currentSession?.session.accessToken)
    }

    func getJWKS() async throws -> BetterAuthJWKS {
        try await makeSessionAdministrationService().getJWKS()
    }

    // MARK: - Linked Accounts

    func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await makeProfileService().listLinkedAccounts(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await makeProfileService().linkSocialAccount(payload,
                                                         accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Passkeys

    func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await makePasskeyService().passkeyRegistrationOptions(request,
                                                                  accessToken: state.currentSession?.session
                                                                      .accessToken)
    }

    func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await makePasskeyService()
            .passkeyAuthenticateOptions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await makePasskeyService().registerPasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        try await makePasskeyService().authenticateWithPasskey(payload)
    }

    func listPasskeys() async throws -> [Passkey] {
        try await makePasskeyService().listPasskeys(accessToken: state.currentSession?.session.accessToken)
    }

    func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        try await makePasskeyService().updatePasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool {
        try await makePasskeyService().deletePasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }
}
