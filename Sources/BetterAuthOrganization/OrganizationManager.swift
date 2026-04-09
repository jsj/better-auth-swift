import BetterAuth
import Foundation

public actor OrganizationManager {
    private let client: BetterAuthClient

    public init(client: BetterAuthClient) {
        self.client = client
    }

    // MARK: - Organization CRUD

    @discardableResult
    public func createOrganization(_ payload: CreateOrganizationRequest) async throws -> Organization {
        try await client.requests.sendJSON(path: "/api/auth/organization/create",
                                           method: "POST",
                                           body: payload)
    }

    public func listOrganizations() async throws -> [Organization] {
        try await client.requests.sendJSON(path: "/api/auth/organization/list",
                                           method: "GET")
    }

    public func getFullOrganization(organizationId: String) async throws -> Organization {
        let response: FullOrganizationResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/get-full-organization",
            method: "GET",
            body: OrganizationIdRequest(organizationId: organizationId)
        )
        return response.organization
    }

    @discardableResult
    public func updateOrganization(_ payload: UpdateOrganizationRequest) async throws -> Organization {
        try await client.requests.sendJSON(path: "/api/auth/organization/update",
                                           method: "POST",
                                           body: payload)
    }

    @discardableResult
    public func deleteOrganization(organizationId: String) async throws -> Bool {
        let response: StatusResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/delete",
            method: "POST",
            body: OrganizationIdRequest(organizationId: organizationId)
        )
        return response.status ?? false
    }

    public func checkSlug(_ slug: String) async throws -> Bool {
        let response: SlugAvailabilityResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/check-slug",
            method: "POST",
            body: SlugCheckRequest(slug: slug)
        )
        return response.status
    }

    // MARK: - Members

    public func listMembers(organizationId: String) async throws -> [OrganizationMember] {
        try await client.requests.sendJSON(
            path: "/api/auth/organization/list-members",
            method: "GET",
            body: OrganizationIdRequest(organizationId: organizationId)
        )
    }

    @discardableResult
    public func removeMember(_ payload: RemoveMemberRequest) async throws -> Bool {
        let response: StatusResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/remove-member",
            method: "POST",
            body: payload
        )
        return response.status ?? false
    }

    @discardableResult
    public func updateMemberRole(_ payload: UpdateMemberRoleRequest) async throws -> OrganizationMember {
        try await client.requests.sendJSON(path: "/api/auth/organization/update-member-role",
                                           method: "POST",
                                           body: payload)
    }

    // MARK: - Invitations

    @discardableResult
    public func inviteMember(_ payload: InviteMemberRequest) async throws -> OrganizationInvitation {
        try await client.requests.sendJSON(path: "/api/auth/organization/invite-member",
                                           method: "POST",
                                           body: payload)
    }

    @discardableResult
    public func acceptInvitation(invitationId: String) async throws -> OrganizationMember {
        try await client.requests.sendJSON(path: "/api/auth/organization/accept-invitation",
                                           method: "POST",
                                           body: InvitationIdRequest(invitationId: invitationId))
    }

    @discardableResult
    public func cancelInvitation(invitationId: String) async throws -> Bool {
        let response: StatusResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/cancel-invitation",
            method: "POST",
            body: InvitationIdRequest(invitationId: invitationId)
        )
        return response.status ?? false
    }

    @discardableResult
    public func rejectInvitation(invitationId: String) async throws -> Bool {
        let response: StatusResponse = try await client.requests.sendJSON(
            path: "/api/auth/organization/reject-invitation",
            method: "POST",
            body: InvitationIdRequest(invitationId: invitationId)
        )
        return response.status ?? false
    }

    public func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        try await client.requests.sendJSON(
            path: "/api/auth/organization/list-invitations",
            method: "GET",
            body: OrganizationIdRequest(organizationId: organizationId)
        )
    }

    // MARK: - Active Organization

    @discardableResult
    public func setActiveOrganization(organizationId: String) async throws -> Organization {
        try await client.requests.sendJSON(path: "/api/auth/organization/set-active",
                                           method: "POST",
                                           body: OrganizationIdRequest(organizationId: organizationId))
    }

    public func getActiveMember() async throws -> OrganizationMember {
        try await client.requests.sendJSON(path: "/api/auth/organization/get-active-member",
                                           method: "GET")
    }
}

// MARK: - Internal Request Types

private struct OrganizationIdRequest: Encodable, Sendable {
    let organizationId: String
}

private struct InvitationIdRequest: Encodable, Sendable {
    let invitationId: String
}

private struct SlugCheckRequest: Encodable, Sendable {
    let slug: String
}

private struct SlugAvailabilityResponse: Decodable, Sendable {
    let status: Bool
}
