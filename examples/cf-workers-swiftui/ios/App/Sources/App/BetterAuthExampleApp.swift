import SwiftUI

@main
struct BetterAuthExampleApp: App {
    @State private var viewModel: AuthViewModel
    @State private var launchError: String?

    init() {
        do {
            let configuration = try AuthConfiguration()
            _viewModel = State(initialValue: AuthViewModel(configuration: configuration))
            _launchError = State(initialValue: nil)
        } catch {
            let fallbackConfiguration = AuthConfiguration(apiBaseURL: URL(string: "http://127.0.0.1:8787")!,
                                                          source: .developmentDefault)
            _viewModel = State(initialValue: AuthViewModel(configuration: fallbackConfiguration))
            _launchError = State(initialValue: error.localizedDescription)
        }
    }

    var body: some Scene {
        WindowGroup {
            AppRootView(launchError: launchError)
                .environment(viewModel)
        }
    }
}
