import BetterAuth
import SwiftUI

struct AuthOptionDetailView: View {
    let option: AuthOption
    let viewModel: AuthViewModel

    var body: some View {
        List {
            Section {
                Text(option.subtitle)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            authSections(for: option)
        }
        .navigationTitle(option.title)
    }

    @ViewBuilder
    private func authSections(for option: AuthOption) -> some View {
        switch option {
        case .authMethod(.apple):
            AppleAuthSection(viewModel: viewModel)

        case .authMethod(.emailPassword):
            EmailPasswordAuthSection(viewModel: viewModel)

        case .authMethod(.usernamePassword):
            UsernameAuthSection(viewModel: viewModel)

        case .authMethod(.magicLink):
            MagicLinkAuthSection(viewModel: viewModel)

        case .authMethod(.emailOTP):
            EmailOTPAuthSection(viewModel: viewModel)

        case .authMethod(.phoneOTP):
            PhoneOTPAuthSection(viewModel: viewModel)

        case .authMethod(.twoFactor):
            TwoFactorAuthSection(viewModel: viewModel)

        case .emailVerification:
            EmailVerificationAuthSection(viewModel: viewModel)

        case .profile:
            ProfileAuthSection(viewModel: viewModel)

        case .sessionManagement:
            SessionManagementAuthSection(viewModel: viewModel)

        case .linkedAccounts:
            LinkedAccountsAuthSection(viewModel: viewModel)

        case .socialOAuth:
            SocialOAuthAuthSection(viewModel: viewModel)

        case .sessionAdmin:
            SessionAdminAuthSection(viewModel: viewModel)

        case .authMethod(.passkey):
            PasskeysAuthSection(viewModel: viewModel)

        case .jwt:
            JWTAuthSection(viewModel: viewModel)

        case .authMethod(.anonymous):
            AnonymousAuthSection(viewModel: viewModel)
        }
    }
}
