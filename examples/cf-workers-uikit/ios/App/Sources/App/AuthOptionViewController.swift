import AuthenticationServices
import UIKit

@MainActor
final class AuthOptionViewController: UITableViewController, ASAuthorizationControllerPresentationContextProviding {
    private let controller: AuthOptionController
    private let option: AuthOption
    private var sections: [AuthOptionSectionModel] = []
    private var appleAuthorizationDelegate: AppleAuthorizationDelegate?

    init(viewModel: AuthViewModel, option: AuthOption) {
        controller = AuthOptionController(viewModel: viewModel)
        self.option = option
        super.init(style: .insetGrouped)
        title = option.title
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
        tableView.register(AuthTextFieldCell.self, forCellReuseIdentifier: AuthTextFieldCell.reuseIdentifier)
        sections = controller.sections(for: option)
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        sections.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].rows.count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].title
    }

    override func tableView(_ tableView: UITableView,
                            cellForRowAt indexPath: IndexPath) -> UITableViewCell
    {
        switch sections[indexPath.section].rows[indexPath.row] {
        case let .field(field):
            let cell = tableView.dequeueReusableCell(withIdentifier: AuthTextFieldCell.reuseIdentifier,
                                                     for: indexPath) as! AuthTextFieldCell
            cell.configure(field: field, viewModel: controller.viewModel)
            return cell

        case let .action(model):
            let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
            var content = cell.defaultContentConfiguration()
            content.textProperties.numberOfLines = 0
            content.secondaryTextProperties.numberOfLines = 0
            content.secondaryTextProperties.color = .secondaryLabel
            content.text = model.title
            content.secondaryText = model.detail
            content.image = UIImage(systemName: model.symbolName)
            content.imageProperties.tintColor = .tintColor
            cell.accessoryType = .none
            cell.selectionStyle = .default
            cell.contentConfiguration = content
            return cell

        case let .info(title, detail, symbolName, tintColor):
            let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
            var content = cell.defaultContentConfiguration()
            content.textProperties.numberOfLines = 0
            content.secondaryTextProperties.numberOfLines = 0
            content.secondaryTextProperties.color = .secondaryLabel
            content.text = title
            content.secondaryText = detail
            if let symbolName {
                content.image = UIImage(systemName: symbolName)
                content.imageProperties.tintColor = tintColor ?? .tintColor
            }
            if let tintColor {
                content.textProperties.color = tintColor
                content.secondaryTextProperties.color = tintColor
            }
            cell.selectionStyle = .none
            cell.contentConfiguration = content
            return cell

        case let .bullet(value, symbolName):
            let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
            var content = cell.defaultContentConfiguration()
            content.textProperties.numberOfLines = 0
            content.secondaryTextProperties.numberOfLines = 0
            content.secondaryTextProperties.color = .secondaryLabel
            content.text = value
            content.secondaryText = nil
            if let symbolName {
                content.image = UIImage(systemName: symbolName)
                content.imageProperties.tintColor = .tintColor
            }
            cell.selectionStyle = .none
            cell.contentConfiguration = content
            return cell
        }
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        defer { tableView.deselectRow(at: indexPath, animated: true) }
        guard case let .action(model) = sections[indexPath.section].rows[indexPath.row] else { return }

        if model.action == .appleSignIn {
            presentAppleSignIn()
            return
        }

        Task {
            await controller.perform(model.action)
            sections = controller.sections(for: option)
            tableView.reloadData()
        }
    }

    private func presentAppleSignIn() {
        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        controller.viewModel.prepareAppleRequest(request)
        let authorizationController = ASAuthorizationController(authorizationRequests: [request])
        authorizationController.presentationContextProvider = self
        let delegate = AppleAuthorizationDelegate(owner: self)
        appleAuthorizationDelegate = delegate
        authorizationController.delegate = delegate
        authorizationController.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        view.window ?? ASPresentationAnchor()
    }

    func handleAppleAuthorization(result: Result<ASAuthorization, Error>) {
        Task {
            await controller.viewModel.handleAppleResult(result)
            sections = self.controller.sections(for: option)
            tableView.reloadData()
        }
    }
}

private final class AppleAuthorizationDelegate: NSObject, ASAuthorizationControllerDelegate {
    weak var owner: AuthOptionViewController?

    init(owner: AuthOptionViewController) {
        self.owner = owner
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithAuthorization authorization: ASAuthorization)
    {
        owner?.handleAppleAuthorization(result: .success(authorization))
    }

    func authorizationController(controller: ASAuthorizationController,
                                 didCompleteWithError error: Error)
    {
        owner?.handleAppleAuthorization(result: .failure(error))
    }
}

final class AuthTextFieldCell: UITableViewCell, UITextFieldDelegate {
    static let reuseIdentifier = "AuthTextFieldCell"

    private let titleLabel = UILabel()
    private let textField = UITextField()
    private var field: AuthFieldModel?
    private weak var viewModel: AuthViewModel?

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        selectionStyle = .none

        titleLabel.font = .preferredFont(forTextStyle: .subheadline)
        titleLabel.textColor = .secondaryLabel

        textField.borderStyle = .roundedRect
        textField.addTarget(self, action: #selector(textChanged), for: .editingChanged)
        textField.delegate = self

        let stack = UIStackView(arrangedSubviews: [titleLabel, textField])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(stack)

        NSLayoutConstraint
            .activate([stack.leadingAnchor.constraint(equalTo: contentView.layoutMarginsGuide.leadingAnchor),
                       stack.trailingAnchor
                           .constraint(equalTo: contentView.layoutMarginsGuide.trailingAnchor),
                       stack.topAnchor.constraint(equalTo: contentView.layoutMarginsGuide.topAnchor),
                       stack.bottomAnchor
                           .constraint(equalTo: contentView.layoutMarginsGuide.bottomAnchor)])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(field: AuthFieldModel, viewModel: AuthViewModel) {
        self.field = field
        self.viewModel = viewModel
        titleLabel.text = field.label
        textField.text = viewModel[keyPath: field.keyPath]
        textField.placeholder = field.label
        textField.keyboardType = field.keyboard
        textField.textContentType = field.secure ? .password : nil
        textField.isSecureTextEntry = field.secure
        textField.autocapitalizationType = field.autocapitalization
        textField.autocorrectionType = .no
    }

    @objc
    private func textChanged() {
        guard let field, let viewModel else { return }
        viewModel[keyPath: field.keyPath] = textField.text ?? ""
    }
}
