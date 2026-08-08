import BetterAuth

public extension AuthStore {
    func changePassword(_ payload: ChangePasswordRequest) async {
        await perform(status: "Password changed") {
            _ = try await accountAuth.changePassword(payload)
        }
    }

    func deleteUser(_ payload: DeleteUserRequest = .init()) async {
        await perform(status: "Account deleted") {
            _ = try await accountAuth.deleteUser(payload)
        }
    }
}
