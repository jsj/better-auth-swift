import BetterAuth
import Foundation

public actor OrganizationManager {
    private let requests: any BetterAuthRequestPerforming

    public init(client: some BetterAuthClientProtocol) {
        requests = client.requestsPerformer
    }

    // MARK: - Organization CRUD

    @discardableResult
    public func createOrganization(_ payload: CreateOrganizationRequest) async throws -> Organization {
        try await requests.sendJSON(path: "/api/auth/organization/create",
                                    method: "POST",
                                    body: payload)
    }

    public func listOrganizations() async throws -> [Organization] {
        try await requests.sendJSON(path: "/api/auth/organization/list",
                                    method: "GET")
    }

    public func getFullOrganization(organizationId: String) async throws -> FullOrganization {
        try await requests.sendJSON(path: try path("/api/auth/organization/get-full-organization",
                                                   queryItems: [URLQueryItem(name: "organizationId",
                                                                             value: organizationId)]),
                                    method: "GET")
    }

    @discardableResult
    public func updateOrganization(_ payload: UpdateOrganizationRequest) async throws -> Organization {
        try await requests.sendJSON(path: "/api/auth/organization/update",
                                    method: "POST",
                                    body: payload)
    }

    @discardableResult
    public func deleteOrganization(organizationId: String) async throws -> Bool {
        let response: StatusResponse = try await requests.sendJSON(path: "/api/auth/organization/delete",
                                                                   method: "POST",
                                                                   body: OrganizationIdRequest(organizationId: organizationId))
        return response.status ?? false
    }

    public func checkSlug(_ slug: String) async throws -> Bool {
        let response: SlugAvailabilityResponse = try await requests.sendJSON(path: "/api/auth/organization/check-slug",
                                                                             method: "POST",
                                                                             body: SlugCheckRequest(slug: slug))
        return response.status
    }

    // MARK: - Members

    public func listMembers(organizationId: String) async throws -> [OrganizationMember] {
        try await requests.sendJSON(path: try path("/api/auth/organization/list-members",
                                                   queryItems: [URLQueryItem(name: "organizationId",
                                                                             value: organizationId)]),
                                    method: "GET")
    }

    @discardableResult
    public func removeMember(_ payload: RemoveMemberRequest) async throws -> Bool {
        let response: StatusResponse = try await requests.sendJSON(path: "/api/auth/organization/remove-member",
                                                                   method: "POST",
                                                                   body: payload)
        return response.status ?? false
    }

    @discardableResult
    public func updateMemberRole(_ payload: UpdateMemberRoleRequest) async throws -> OrganizationMember {
        try await requests.sendJSON(path: "/api/auth/organization/update-member-role",
                                    method: "POST",
                                    body: payload)
    }

    // MARK: - Invitations

    @discardableResult
    public func inviteMember(_ payload: InviteMemberRequest) async throws -> OrganizationInvitation {
        try await requests.sendJSON(path: "/api/auth/organization/invite-member",
                                    method: "POST",
                                    body: payload)
    }

    @discardableResult
    public func acceptInvitation(invitationId: String) async throws -> OrganizationMember {
        try await requests.sendJSON(path: "/api/auth/organization/accept-invitation",
                                    method: "POST",
                                    body: InvitationIdRequest(invitationId: invitationId))
    }

    @discardableResult
    public func cancelInvitation(invitationId: String) async throws -> Bool {
        let response: StatusResponse = try await requests.sendJSON(path: "/api/auth/organization/cancel-invitation",
                                                                   method: "POST",
                                                                   body: InvitationIdRequest(invitationId: invitationId))
        return response.status ?? false
    }

    @discardableResult
    public func rejectInvitation(invitationId: String) async throws -> Bool {
        let response: StatusResponse = try await requests.sendJSON(path: "/api/auth/organization/reject-invitation",
                                                                   method: "POST",
                                                                   body: InvitationIdRequest(invitationId: invitationId))
        return response.status ?? false
    }

    public func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        try await requests.sendJSON(path: try path("/api/auth/organization/list-invitations",
                                                   queryItems: [URLQueryItem(name: "organizationId",
                                                                             value: organizationId)]),
                                    method: "GET")
    }

    // MARK: - Active Organization

    @discardableResult
    public func setActiveOrganization(organizationId: String) async throws -> Organization {
        try await requests.sendJSON(path: "/api/auth/organization/set-active",
                                    method: "POST",
                                    body: OrganizationIdRequest(organizationId: organizationId))
    }

    public func getActiveMember() async throws -> OrganizationMember {
        try await requests.sendJSON(path: "/api/auth/organization/get-active-member",
                                    method: "GET")
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
