import UIKit

@MainActor
final class AuthOptionsViewController: UITableViewController {
    private let controller: AuthOptionsController
    private let launchError: String?

    init(viewModel: AuthViewModel, launchError: String?) {
        controller = AuthOptionsController(viewModel: viewModel)
        self.launchError = launchError
        super.init(style: .insetGrouped)
        title = "Better Auth"
        navigationItem.largeTitleDisplayMode = .always
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
        configureNavigationItems()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !controller.viewModel.isReady else { return }
        Task {
            await controller.restore()
            tableView.reloadData()
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return 3
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch section {
        case 0:
            return 1
        case 1:
            var count = controller.viewModel.statusMessage == nil ? 0 : 1
            if launchError != nil { count += 1 }
            return count
        case 2:
            return AuthOption.allCases.count
        default:
            return 0
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0:
            "Worker"
        case 1:
            "Status"
        case 2:
            "Auth Options"
        default:
            nil
        }
    }

    override func tableView(
        _ tableView: UITableView,
        cellForRowAt indexPath: IndexPath
    ) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        var content = cell.defaultContentConfiguration()
        content.textProperties.numberOfLines = 0
        content.secondaryTextProperties.numberOfLines = 0
        cell.accessoryType = .none

        switch indexPath.section {
        case 0:
            content.text = controller.viewModel.configuration.displayBaseURL
            content.secondaryText = controller.viewModel.workerReachability.statusText
            content.image = UIImage(systemName: workerStatusSymbolName)
            content.imageProperties.tintColor = workerStatusColor
            content.secondaryTextProperties.color = workerStatusColor
        case 1:
            let messages = statusMessages()
            content.text = messages[indexPath.row]
            content.image = UIImage(systemName: statusSymbolName(for: messages[indexPath.row]))
            content.imageProperties.tintColor = statusColor(for: messages[indexPath.row])
            content.textProperties.color = statusColor(for: messages[indexPath.row])
            content.secondaryText = nil
        case 2:
            let option = AuthOption.allCases[indexPath.row]
            content.text = option.title
            content.secondaryText = option.subtitle
            content.image = UIImage(systemName: option.symbolName)
            content.imageProperties.tintColor = .tintColor
            content.secondaryTextProperties.color = .secondaryLabel
            cell.accessoryType = .disclosureIndicator
        default:
            break
        }

        cell.contentConfiguration = content
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        defer { tableView.deselectRow(at: indexPath, animated: true) }
        guard indexPath.section == 2 else { return }
        let option = AuthOption.allCases[indexPath.row]
        navigationController?.pushViewController(
            AuthOptionViewController(viewModel: controller.viewModel, option: option),
            animated: true
        )
    }

    private func configureNavigationItems() {
        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(
                title: "Sign Out",
                style: .plain,
                target: self,
                action: #selector(signOutTapped)
            ),
            UIBarButtonItem(
                title: "Refresh",
                style: .plain,
                target: self,
                action: #selector(refreshTapped)
            )
        ]
    }

    private func statusMessages() -> [String] {
        var messages: [String] = []
        if let launchError {
            messages.append(launchError)
        }
        if let statusMessage = controller.viewModel.statusMessage {
            messages.append(statusMessage)
        }
        return messages
    }

    private var workerStatusColor: UIColor {
        switch controller.viewModel.workerReachability {
        case .checking:
            return .systemOrange
        case .reachable:
            return .systemGreen
        case .unreachable:
            return .systemRed
        }
    }

    private var workerStatusSymbolName: String {
        switch controller.viewModel.workerReachability {
        case .checking:
            return "clock.badge.questionmark"
        case .reachable:
            return "checkmark.circle.fill"
        case .unreachable:
            return "xmark.octagon.fill"
        }
    }

    private func statusColor(for message: String) -> UIColor {
        let text = message.lowercased()
        if text.contains("error") || text.contains("invalid") || text.contains("failed") || text.contains("missing") || text.contains("unreachable") {
            return .systemRed
        }
        if text.contains("signed in") || text.contains("restored") || text.contains("verified") || text.contains("loaded") || text.contains("enabled") {
            return .systemGreen
        }
        return .systemOrange
    }

    private func statusSymbolName(for message: String) -> String {
        let text = message.lowercased()
        if text.contains("error") || text.contains("invalid") || text.contains("failed") || text.contains("missing") || text.contains("unreachable") {
            return "exclamationmark.triangle.fill"
        }
        if text.contains("signed in") || text.contains("restored") || text.contains("verified") || text.contains("loaded") || text.contains("enabled") {
            return "checkmark.circle.fill"
        }
        return "info.circle.fill"
    }

    @objc
    private func refreshTapped() {
        Task {
            await controller.refresh()
            tableView.reloadData()
        }
    }

    @objc
    private func signOutTapped() {
        Task {
            await controller.signOut()
            tableView.reloadData()
        }
    }
}
