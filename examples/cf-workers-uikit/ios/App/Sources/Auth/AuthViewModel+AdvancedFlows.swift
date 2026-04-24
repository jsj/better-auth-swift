import BetterAuth
import Foundation

extension AuthViewModel {
    // MARK: - Auth Exploration

    private func updateAuthorizationURL(_ url: String?, status: String) {
        lastAuthorizationURL = url
        statusMessage = status
    }

    func loadLinkedAccounts() async {
        await perform {
            linkedAccounts = try await service.listLinkedAccounts()
            statusMessage = "\(linkedAccounts.count) linked account(s)"
        }
    }

    func signInWithGoogle() async {
        await perform {
            let result = try await service.signInWithSocial(.init(provider: "google", disableRedirect: true))
            switch result {
            case let .authorizationURL(response):
                updateAuthorizationURL(response.url, status: "Google auth URL ready")

            case let .signedIn(response):
                updateAuthorizationURL(response.url,
                                       status: "Signed in with Google token \(response.token.prefix(12))…")
            }
        }
    }

    func beginGenericOAuth() async {
        await perform {
            let response = try await service.beginGenericOAuth(.init(providerId: "fixture-generic",
                                                                     callbackURL: "betterauth://oauth/success",
                                                                     disableRedirect: true))
            updateAuthorizationURL(response.url, status: "Generic OAuth URL ready")
        }
    }

    func linkGenericOAuth() async {
        await perform {
            let response = try await service.linkGenericOAuth(.init(providerId: "fixture-generic",
                                                                    callbackURL: "betterauth://oauth/success",
                                                                    disableRedirect: true))
            updateAuthorizationURL(response.url, status: "Generic OAuth link URL ready")
        }
    }

    func completeGenericOAuth() async {
        await perform {
            session = try await service.completeGenericOAuth(.init(providerId: "fixture-generic",
                                                                   code: tokenInput
                                                                       .isEmpty ? "fixture-code" : tokenInput,
                                                                   state: usernameInput
                                                                       .isEmpty ? "fixture-state" : usernameInput))
            if let session {
                launchState = .authenticated(session)
            }
            statusMessage = "Generic OAuth completed"
        }
    }

    func linkGoogleAccount() async {
        await perform {
            let response = try await service.linkSocialAccount(.init(provider: "google", disableRedirect: true))
            updateAuthorizationURL(response.url,
                                   status: response.status == true ? "Google account linked" : "Google link URL ready")
        }
    }

    func reauthenticate() async {
        await perform {
            let ok = try await service.reauthenticate(password: passwordInput)
            statusMessage = ok ? "Reauthentication succeeded" : "Reauthentication incomplete"
        }
    }

    func loadPasskeys() async {
        await perform {
            passkeys = try await service.listPasskeys()
            statusMessage = "\(passkeys.count) passkey(s) loaded"
        }
    }

    private func requireFirstPasskey() -> Passkey? {
        guard let first = passkeys.first else {
            statusMessage = "Load passkeys first"
            return nil
        }
        return first
    }

    func loadPasskeyRegistrationOptions() async {
        await perform {
            let options = try await service.passkeyRegistrationOptions()
            statusMessage = "Passkey challenge \(options.challenge.prefix(16))…"
        }
    }

    func registerExamplePasskey() async {
        await perform {
            let passkey = try await service.registerPasskey(name: nameInput.isEmpty ? "Example Passkey" : nameInput)
            statusMessage = "Registered passkey \(passkey.name ?? passkey.id)"
        }
    }

    func authenticateWithExamplePasskey() async {
        await perform {
            session = try await service.authenticateWithPasskey()
            if let session {
                launchState = .authenticated(session)
            }
            statusMessage = "Authenticated with passkey"
        }
    }

    func renameFirstPasskey() async {
        guard let first = requireFirstPasskey() else { return }
        await perform {
            let updated = try await service.updatePasskey(id: first.id,
                                                          name: nameInput.isEmpty ? "Renamed Passkey" : nameInput)
            if let index = passkeys.firstIndex(where: { $0.id == updated.id }) {
                passkeys[index] = updated
            }
            statusMessage = "Passkey renamed"
        }
    }

    func deleteFirstPasskey() async {
        guard let first = requireFirstPasskey() else { return }
        await perform {
            try await service.deletePasskey(id: first.id)
            passkeys.removeAll { $0.id == first.id }
            statusMessage = "Passkey deleted"
        }
    }

    private func requireFirstDeviceSession() -> BetterAuthDeviceSession? {
        guard let first = deviceSessions.first else {
            statusMessage = "Load device sessions first"
            return nil
        }
        guard first.session.token != nil else {
            statusMessage = "Selected device session has no token"
            return nil
        }
        return first
    }

    func activateFirstDeviceSession() async {
        guard let first = requireFirstDeviceSession(), let token = first.session.token else { return }
        await perform {
            session = try await service.setActiveDeviceSession(sessionToken: token)
            if let session {
                launchState = .authenticated(session)
            }
            statusMessage = "Active device session switched"
        }
    }

    func revokeFirstDeviceSession() async {
        guard let first = requireFirstDeviceSession(), let token = first.session.token else { return }
        await perform {
            try await service.revokeDeviceSession(sessionToken: token)
            deviceSessions.removeAll { $0.session.id == first.session.id }
            statusMessage = "Device session revoked"
        }
    }

    private func requireFirstSessionEntry() -> BetterAuthSessionListEntry? {
        guard let first = sessionList.first else {
            statusMessage = "Load sessions first"
            return nil
        }
        guard first.token != nil else {
            statusMessage = "Selected session has no token"
            return nil
        }
        return first
    }

    func revokeFirstSession() async {
        guard let first = requireFirstSessionEntry(), let token = first.token else { return }
        await perform {
            try await service.revokeSession(token: token)
            sessionList.removeAll { $0.id == first.id }
            statusMessage = "Session revoked"
        }
    }

    func loadJWT() async {
        await perform {
            let jwt = try await service.getSessionJWT()
            jwtToken = jwt.token
            statusMessage = "JWT loaded"
        }
    }

    func loadJWKS() async {
        await perform {
            jwksKeys = try await service.getJWKS().keys
            statusMessage = "JWKS loaded"
        }
    }
}
