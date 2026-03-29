import BetterAuth
import SwiftUI

struct SessionSummarySection: View {
    let viewModel: AuthViewModel
    let session: BetterAuthSession

    var body: some View {
        Section("Session") {
            LabeledContent("User ID", value: session.user.id)
            LabeledContent("Email", value: session.user.email ?? "—")
            LabeledContent("Name", value: session.user.name ?? "—")
            LabeledContent("Session ID", value: session.session.id)
            LabeledContent("Token", value: String(session.session.accessToken.prefix(24)) + "…")
            if let expiresAt = session.session.expiresAt {
                LabeledContent("Expires", value: expiresAt.formatted(.relative(presentation: .named)))
            }
            Button("Refresh Session") { Task { await viewModel.refresh() } }
                .disabled(viewModel.isPerformingAuthAction)
            Button("Sign Out", role: .destructive) { Task { await viewModel.signOut() } }
                .disabled(viewModel.isPerformingAuthAction)
        }
    }
}
