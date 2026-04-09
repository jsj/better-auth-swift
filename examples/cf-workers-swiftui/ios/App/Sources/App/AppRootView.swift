import SwiftUI

struct AppRootView: View {
    @Environment(AuthViewModel.self) private var viewModel
    let launchError: String?

    var body: some View {
        ContentView(viewModel: viewModel, launchError: launchError)
            .task {
                guard !viewModel.isReady else { return }
                await viewModel.bootstrap()
            }
            .onOpenURL { url in
                guard viewModel.supportsIncomingURL(url) else { return }
                Task {
                    await viewModel.handleIncomingURL(url)
                }
            }
    }
}
