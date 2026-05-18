import BetterAuth
import Foundation

public actor OrganizationManager {
    private let routes: OrganizationRoutes

    public init(client: some BetterAuthClientProtocol) {
        routes = OrganizationRoutes(requests: client.requestsPerformer)
    }

    // MARK: - Organization CRUD

    @discardableResult
    public func createOrganization(_ payload: CreateOrganizationRequest) async throws -> Organization {
        try await routes.createOrganization(payload)
    }

    public func listOrganizations() async throws -> [Organization] {
        try await routes.listOrganizations()
    }

    public func getFullOrganization(organizationId: String) async throws -> FullOrganization {
        try await routes.getFullOrganization(organizationId: organizationId)
    }

    @discardableResult
    public func updateOrganization(_ payload: UpdateOrganizationRequest) async throws -> Organization {
        try await routes.updateOrganization(payload)
    }

    @discardableResult
    public func deleteOrganization(organizationId: String) async throws -> Bool {
        try await routes.deleteOrganization(organizationId: organizationId)
    }

    public func checkSlug(_ slug: String) async throws -> Bool {
        try await routes.checkSlug(slug)
    }

    // MARK: - Members

    public func listMembers(organizationId: String) async throws -> [OrganizationMember] {
        try await routes.listMembers(organizationId: organizationId)
    }

    @discardableResult
    public func removeMember(_ payload: RemoveMemberRequest) async throws -> Bool {
        try await routes.removeMember(payload)
    }

    @discardableResult
    public func updateMemberRole(_ payload: UpdateMemberRoleRequest) async throws -> OrganizationMember {
        try await routes.updateMemberRole(payload)
    }

    // MARK: - Invitations

    @discardableResult
    public func inviteMember(_ payload: InviteMemberRequest) async throws -> OrganizationInvitation {
        try await routes.inviteMember(payload)
    }

    @discardableResult
    public func acceptInvitation(invitationId: String) async throws -> OrganizationMember {
        try await routes.acceptInvitation(invitationId: invitationId)
    }

    @discardableResult
    public func cancelInvitation(invitationId: String) async throws -> Bool {
        try await routes.cancelInvitation(invitationId: invitationId)
    }

    @discardableResult
    public func rejectInvitation(invitationId: String) async throws -> Bool {
        try await routes.rejectInvitation(invitationId: invitationId)
    }

    public func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        try await routes.listInvitations(organizationId: organizationId)
    }

    // MARK: - Active Organization

    @discardableResult
    public func setActiveOrganization(organizationId: String) async throws -> Organization {
        try await routes.setActiveOrganization(organizationId: organizationId)
    }

    public func getActiveMember() async throws -> OrganizationMember {
        try await routes.getActiveMember()
    }
}

struct OrganizationRoutes {
    private let requests: any BetterAuthRequestPerforming

    init(requests: any BetterAuthRequestPerforming) {
        self.requests = requests
    }

    func createOrganization(_ payload: CreateOrganizationRequest) async throws -> Organization {
        try await post("/api/auth/organization/create", body: payload)
    }

    func listOrganizations() async throws -> [Organization] {
        try await get("/api/auth/organization/list")
    }

    func getFullOrganization(organizationId: String) async throws -> FullOrganization {
        try await get(try path("/api/auth/organization/get-full-organization",
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    func updateOrganization(_ payload: UpdateOrganizationRequest) async throws -> Organization {
        try await post("/api/auth/organization/update", body: payload)
    }

    func deleteOrganization(organizationId: String) async throws -> Bool {
        try await status(path: "/api/auth/organization/delete",
                         body: OrganizationIdRequest(organizationId: organizationId))
    }

    func checkSlug(_ slug: String) async throws -> Bool {
        let response: SlugAvailabilityResponse = try await post("/api/auth/organization/check-slug",
                                                                body: SlugCheckRequest(slug: slug))
        return response.status
    }

    func listMembers(organizationId: String) async throws -> [OrganizationMember] {
        try await get(try path("/api/auth/organization/list-members",
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    func removeMember(_ payload: RemoveMemberRequest) async throws -> Bool {
        try await status(path: "/api/auth/organization/remove-member", body: payload)
    }

    func updateMemberRole(_ payload: UpdateMemberRoleRequest) async throws -> OrganizationMember {
        try await post("/api/auth/organization/update-member-role", body: payload)
    }

    func inviteMember(_ payload: InviteMemberRequest) async throws -> OrganizationInvitation {
        try await post("/api/auth/organization/invite-member", body: payload)
    }

    func acceptInvitation(invitationId: String) async throws -> OrganizationMember {
        try await post("/api/auth/organization/accept-invitation",
                       body: InvitationIdRequest(invitationId: invitationId))
    }

    func cancelInvitation(invitationId: String) async throws -> Bool {
        try await status(path: "/api/auth/organization/cancel-invitation",
                         body: InvitationIdRequest(invitationId: invitationId))
    }

    func rejectInvitation(invitationId: String) async throws -> Bool {
        try await status(path: "/api/auth/organization/reject-invitation",
                         body: InvitationIdRequest(invitationId: invitationId))
    }

    func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        try await get(try path("/api/auth/organization/list-invitations",
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    func setActiveOrganization(organizationId: String) async throws -> Organization {
        try await post("/api/auth/organization/set-active",
                       body: OrganizationIdRequest(organizationId: organizationId))
    }

    func getActiveMember() async throws -> OrganizationMember {
        try await get("/api/auth/organization/get-active-member")
    }

    private func get<Response: Decodable>(_ path: String) async throws -> Response {
        try await requests.sendJSON(path: path, method: "GET")
    }

    private func post<Response: Decodable>(_ path: String, body: some Encodable) async throws -> Response {
        try await requests.sendJSON(path: path, method: "POST", body: body)
    }

    private func status(path: String, body: some Encodable) async throws -> Bool {
        let response: StatusResponse = try await post(path, body: body)
        return response.status ?? false
    }

    private func path(_ base: String, queryItems: [URLQueryItem]) throws -> String {
        var components = URLComponents()
        components.path = base
        components.queryItems = queryItems
        guard let path = components.string else {
            throw BetterAuthError.invalidURL
        }
        return path
    }
}

// MARK: - Internal Request Types

private struct OrganizationIdRequest: Encodable {
    let organizationId: String
}

private struct InvitationIdRequest: Encodable {
    let invitationId: String
}

private struct SlugCheckRequest: Encodable {
    let slug: String
}

private struct SlugAvailabilityResponse: Decodable {
    let status: Bool
}
