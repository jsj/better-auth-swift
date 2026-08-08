import Foundation

extension BetterAuthSessionManager {
    @discardableResult
    func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        try await makeProfileService().deleteUser(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Email Verification

    @discardableResult
    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        try await makeProfileService().sendVerificationEmail(payload,
                                                             accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await makeProfileService().verifyEmail(payload)
    }

    @discardableResult
    func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await makeProfileService().changeEmail(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - User Management

    @discardableResult
    func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await makeProfileService().updateUser(payload, currentSession: state.currentSession)
    }

    @discardableResult
    func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await makeProfileService().changePassword(payload, currentSession: state.currentSession)
    }
}
