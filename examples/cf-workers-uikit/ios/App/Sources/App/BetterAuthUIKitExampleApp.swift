import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var viewModel: AuthViewModel?
    private var launchError: String?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool
    {
        let resolvedViewModel: AuthViewModel

        do {
            let configuration = try AuthConfiguration()
            resolvedViewModel = AuthViewModel(configuration: configuration)
            launchError = nil
        } catch {
            let fallbackConfiguration = AuthConfiguration(apiBaseURL: URL(string: "http://127.0.0.1:8787")!,
                                                          source: .developmentDefault)
            resolvedViewModel = AuthViewModel(configuration: fallbackConfiguration)
            launchError = error.localizedDescription
        }

        viewModel = resolvedViewModel

        let navigationController =
            UINavigationController(rootViewController: AuthOptionsViewController(viewModel: resolvedViewModel,
                                                                                 launchError: launchError))
        let window = UIWindow(frame: UIScreen.main.bounds)
        window.rootViewController = navigationController
        window.makeKeyAndVisible()
        self.window = window
        return true
    }

    func application(_ app: UIApplication,
                     open url: URL,
                     options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool
    {
        guard let viewModel, viewModel.supportsIncomingURL(url) else { return false }

        Task {
            await viewModel.handleIncomingURL(url)
            if let navigationController = window?.rootViewController as? UINavigationController,
               let authOptionsViewController = navigationController.viewControllers.first as? AuthOptionsViewController
            {
                authOptionsViewController.reloadState()
            }
        }

        return true
    }
}
