import BetterAuth
import SwiftUI

struct ContentView: View {
    let viewModel: AuthViewModel
    let launchError: String?

    var body: some View {
        NavigationStack {
            List {
                workerSection
                statusSection
                if let session = viewModel.session {
                    SessionSummarySection(viewModel: viewModel, session: session)
                }
                if viewModel.isPerformingAuthAction {
                    loadingSection
                }
                authOptionsSection
            }
            .navigationTitle("Better Auth")
            .refreshable {
                await viewModel.restore()
            }
            .task {
                guard !viewModel.isReady else { return }
                await viewModel.restore()
            }
        }
    }

    private var workerSection: some View {
        Section("Worker") {
            HStack(spacing: 8) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)

                Text(viewModel.configuration.displayBaseURL)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }

            Text(viewModel.workerReachability.statusText)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var statusSection: some View {
        if let launchError {
            Section("Configuration") {
                Text(launchError)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }

        if let status = viewModel.statusMessage {
            Section("Status") {
                Text(status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var loadingSection: some View {
        Section {
            HStack(spacing: 12) {
                ProgressView()
                Text("Working…")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var authOptionsSection: some View {
        Section("Auth Options") {
            ForEach(AuthOption.allCases) { option in
                NavigationLink {
                    AuthOptionDetailView(option: option, viewModel: viewModel)
                } label: {
                    Label(option.title, systemImage: option.symbolName)
                }
            }
        }
    }
}

private extension ContentView {
    var statusColor: Color {
        switch viewModel.workerReachability {
        case .checking:
            .orange
        case .reachable:
            .green
        case .unreachable:
            .red
        }
    }
}

#Preview {
    ContentView(
        viewModel: AuthViewModel(
            configuration: AuthConfiguration(
                apiBaseURL: URL(string: "http://127.0.0.1:8787")!,
                source: .developmentDefault
            )
        ),
        launchError: nil
    )
}
