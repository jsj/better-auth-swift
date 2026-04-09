import BetterAuth
import BetterAuthOrganization
import Foundation
import Testing

private struct MockTransport: BetterAuthTransport {
    let handler: @Sendable (URLRequest) async throws -> (Data, URLResponse)

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await handler(request)
    }
}

private func response(for request: URLRequest, statusCode: Int, data: Data) -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: request.url ?? URL(string: "https://example.com")!,
                                   statusCode: statusCode,
                                   httpVersion: nil,
                                   headerFields: nil)!
    return (data, response)
}

private func encodeJSON(_ value: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

struct OrganizationTests {
    private func makeClient(transport: BetterAuthTransport) throws -> BetterAuthClient {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com", name: "Test User"))
        let store = InMemorySessionStore()
        let client = BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                             storage: .init(key: "test-key")),
                                      sessionStore: store,
                                      transport: transport)
        try store.saveSession(session, for: "test-key")
        return client
    }

    @Test
    func createOrganizationUsesPublicRequestClient() async throws {
        let org = Organization(id: "org-1", name: "Acme", slug: "acme", createdAt: Date())

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/create")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
            return try response(for: request, statusCode: 200, data: encodeJSON(org))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.createOrganization(
            CreateOrganizationRequest(name: "Acme", slug: "acme")
        )
        #expect(result.id == "org-1")
        #expect(result.name == "Acme")
        #expect(result.slug == "acme")
    }

    @Test
    func listOrganizationsDecodesArray() async throws {
        let orgs = [
            Organization(id: "org-1", name: "Acme", slug: "acme", createdAt: Date()),
            Organization(id: "org-2", name: "Beta", slug: "beta", createdAt: Date()),
        ]

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/list")
            #expect(request.httpMethod == "GET")
            return try response(for: request, statusCode: 200, data: encodeJSON(orgs))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.listOrganizations()
        #expect(result.count == 2)
        #expect(result[0].slug == "acme")
        #expect(result[1].slug == "beta")
    }

    @Test
    func deleteOrganizationReturnsStatus() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/delete")
            #expect(request.httpMethod == "POST")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.deleteOrganization(organizationId: "org-1")
        #expect(result == true)
    }

    @Test
    func inviteMemberEncodesPayload() async throws {
        let invitation = OrganizationInvitation(id: "inv-1",
                                                organizationId: "org-1",
                                                email: "new@example.com",
                                                role: "member",
                                                inviterId: "user-1",
                                                expiresAt: Date().addingTimeInterval(86400))

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/invite-member")
            let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            #expect(body?["email"] as? String == "new@example.com")
            #expect(body?["role"] as? String == "member")
            #expect(body?["organizationId"] as? String == "org-1")
            return try response(for: request, statusCode: 200, data: encodeJSON(invitation))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.inviteMember(
            InviteMemberRequest(organizationId: "org-1", email: "new@example.com")
        )
        #expect(result.id == "inv-1")
        #expect(result.email == "new@example.com")
    }

    @Test
    func acceptInvitationReturnsMember() async throws {
        let member = OrganizationMember(id: "member-1",
                                        organizationId: "org-1",
                                        userId: "user-1",
                                        role: "member",
                                        user: .init(id: "user-1", email: "user@example.com", name: "Test User"))

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/accept-invitation")
            let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            #expect(body?["invitationId"] as? String == "inv-1")
            return try response(for: request, statusCode: 200, data: encodeJSON(member))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.acceptInvitation(invitationId: "inv-1")
        #expect(result.id == "member-1")
        #expect(result.role == "member")
        #expect(result.user?.email == "user@example.com")
    }

    @Test
    func setActiveOrganizationReturnsOrg() async throws {
        let org = Organization(id: "org-1", name: "Acme", slug: "acme", createdAt: Date())

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/organization/set-active")
            #expect(request.httpMethod == "POST")
            return try response(for: request, statusCode: 200, data: encodeJSON(org))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)

        let result = try await manager.setActiveOrganization(organizationId: "org-1")
        #expect(result.id == "org-1")
    }

    @Test
    func pluginUsesOnlyPublicAPIWithoutTestableImport() async throws {
        // This test validates the plugin pattern: OrganizationManager uses
        // only public BetterAuth API (BetterAuthClient, requests.sendJSON).
        // If this file compiles without @testable import BetterAuth, the
        // pattern is proven.
        let transport = MockTransport { request in
            response(for: request, statusCode: 200, data: Data("[]".utf8))
        }

        let client = try makeClient(transport: transport)
        _ = try await client.auth.restoreSession()
        let manager = OrganizationManager(client: client)
        let orgs = try await manager.listOrganizations()
        #expect(orgs.isEmpty)
    }
}
