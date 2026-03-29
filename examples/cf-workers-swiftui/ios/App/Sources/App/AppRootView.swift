import SwiftUI

struct AppRootView: View {
    @Environment(AuthViewModel.self) private var viewModel
    let launchError: String?

    var body: some View {
        ContentView(viewModel: viewModel, launchError: launchError)
    }
}
