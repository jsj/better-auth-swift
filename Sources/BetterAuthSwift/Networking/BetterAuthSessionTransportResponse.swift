import Foundation

struct BetterAuthSessionTransportResponse: Decodable {
    let token: String?
    let user: BetterAuthSession.User?
    let session: BetterAuthSession?

    init(from decoder: Decoder) throws {
        if let session = try? BetterAuthSession(from: decoder) {
            token = session.session.accessToken
            user = session.user
            self.session = session
            return
        }
        let value = try Envelope(from: decoder)
        token = value.token
        user = value.user
        session = value.session
    }

    var materializedSession: BetterAuthSession? {
        session
    }

    var signedIn: SignedIn? {
        guard let token, let user else { return nil }
        return SignedIn(token: token, user: user)
    }

    struct SignedIn {
        let token: String
        let user: BetterAuthSession.User
    }

    private struct Envelope: Decodable {
        let token: String?
        let user: BetterAuthSession.User?
        let session: BetterAuthSession?
    }
}
