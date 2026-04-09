import UIKit

@MainActor
final class AuthOptionsController {
    private(set) var viewModel: AuthViewModel

    init(viewModel: AuthViewModel) {
        self.viewModel = viewModel
    }

    func bootstrap() async {
        await viewModel.bootstrap()
    }

    func refresh() async {
        await viewModel.refresh()
    }

    func signOut() async {
        await viewModel.signOut()
    }
}
