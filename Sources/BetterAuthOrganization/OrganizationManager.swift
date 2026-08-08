import BetterAuth
import Foundation

public struct BetterAuthOrganizationEndpoints: Sendable, Equatable {
    public let createPath: String
    public let listPath: String
    public let getFullOrganizationPath: String
    public let updatePath: String
    public let deletePath: String
    public let checkSlugPath: String
    public let listMembersPath: String
    public let removeMemberPath: String
    public let updateMemberRolePath: String
    public let inviteMemberPath: String
    public let acceptInvitationPath: String
    public let cancelInvitationPath: String
    public let rejectInvitationPath: String
    public let listInvitationsPath: String
    public let setActivePath: String
    public let getActiveMemberPath: String

    public init(createPath: String = "/api/auth/organization/create",
                listPath: String = "/api/auth/organization/list",
                getFullOrganizationPath: String = "/api/auth/organization/get-full-organization",
                updatePath: String = "/api/auth/organization/update",
                deletePath: String = "/api/auth/organization/delete",
                checkSlugPath: String = "/api/auth/organization/check-slug",
                listMembersPath: String = "/api/auth/organization/list-members",
                removeMemberPath: String = "/api/auth/organization/remove-member",
                updateMemberRolePath: String = "/api/auth/organization/update-member-role",
                inviteMemberPath: String = "/api/auth/organization/invite-member",
                acceptInvitationPath: String = "/api/auth/organization/accept-invitation",
                cancelInvitationPath: String = "/api/auth/organization/cancel-invitation",
                rejectInvitationPath: String = "/api/auth/organization/reject-invitation",
                listInvitationsPath: String = "/api/auth/organization/list-invitations",
                setActivePath: String = "/api/auth/organization/set-active",
                getActiveMemberPath: String = "/api/auth/organization/get-active-member")
    {
        self.createPath = createPath
        self.listPath = listPath
        self.getFullOrganizationPath = getFullOrganizationPath
        self.updatePath = updatePath
        self.deletePath = deletePath
        self.checkSlugPath = checkSlugPath
        self.listMembersPath = listMembersPath
        self.removeMemberPath = removeMemberPath
        self.updateMemberRolePath = updateMemberRolePath
        self.inviteMemberPath = inviteMemberPath
        self.acceptInvitationPath = acceptInvitationPath
        self.cancelInvitationPath = cancelInvitationPath
        self.rejectInvitationPath = rejectInvitationPath
        self.listInvitationsPath = listInvitationsPath
        self.setActivePath = setActivePath
        self.getActiveMemberPath = getActiveMemberPath
    }
}

public struct OrganizationManager: Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let endpoints: BetterAuthOrganizationEndpoints

    public init(client: some BetterAuthClientProtocol,
                endpoints: BetterAuthOrganizationEndpoints = .init())
    {
        requests = client.requestsPerformer
        self.endpoints = endpoints
    }

    // MARK: - Organization CRUD

    @discardableResult
    public func createOrganization(_ payload: CreateOrganizationRequest) async throws -> Organization {
        try await post(endpoints.createPath, body: payload)
    }

    public func listOrganizations() async throws -> [Organization] {
        try await get(endpoints.listPath)
    }

    public func getFullOrganization(organizationId: String) async throws -> FullOrganization {
        try await get(try path(endpoints.getFullOrganizationPath,
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    @discardableResult
    public func updateOrganization(_ payload: UpdateOrganizationRequest) async throws -> Organization {
        try await post(endpoints.updatePath, body: payload)
    }

    @discardableResult
    public func deleteOrganization(organizationId: String) async throws -> Bool {
        try await status(path: endpoints.deletePath,
                         body: OrganizationIdRequest(organizationId: organizationId))
    }

    public func checkSlug(_ slug: String) async throws -> Bool {
        let response: SlugAvailabilityResponse = try await post(endpoints.checkSlugPath,
                                                                body: SlugCheckRequest(slug: slug))
        return response.status
    }

    // MARK: - Members

    public func listMembers(organizationId: String) async throws -> [OrganizationMember] {
        try await get(try path(endpoints.listMembersPath,
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    @discardableResult
    public func removeMember(_ payload: RemoveMemberRequest) async throws -> Bool {
        try await status(path: endpoints.removeMemberPath, body: payload)
    }

    @discardableResult
    public func updateMemberRole(_ payload: UpdateMemberRoleRequest) async throws -> OrganizationMember {
        try await post(endpoints.updateMemberRolePath, body: payload)
    }

    // MARK: - Invitations

    @discardableResult
    public func inviteMember(_ payload: InviteMemberRequest) async throws -> OrganizationInvitation {
        try await post(endpoints.inviteMemberPath, body: payload)
    }

    @discardableResult
    public func acceptInvitation(invitationId: String) async throws -> OrganizationMember {
        try await post(endpoints.acceptInvitationPath,
                       body: InvitationIdRequest(invitationId: invitationId))
    }

    @discardableResult
    public func cancelInvitation(invitationId: String) async throws -> Bool {
        try await status(path: endpoints.cancelInvitationPath,
                         body: InvitationIdRequest(invitationId: invitationId))
    }

    @discardableResult
    public func rejectInvitation(invitationId: String) async throws -> Bool {
        try await status(path: endpoints.rejectInvitationPath,
                         body: InvitationIdRequest(invitationId: invitationId))
    }

    public func listInvitations(organizationId: String) async throws -> [OrganizationInvitation] {
        try await get(try path(endpoints.listInvitationsPath,
                               queryItems: [URLQueryItem(name: "organizationId", value: organizationId)]))
    }

    // MARK: - Active Organization

    @discardableResult
    public func setActiveOrganization(organizationId: String) async throws -> Organization {
        try await post(endpoints.setActivePath,
                       body: OrganizationIdRequest(organizationId: organizationId))
    }

    public func getActiveMember() async throws -> OrganizationMember {
        try await get(endpoints.getActiveMemberPath)
    }

    private func get<Response: Decodable>(_ path: String) async throws -> Response {
        try await requests.sendJSON(path: path, method: "GET")
    }

    private func post<Response: Decodable>(_ path: String, body: some Encodable) async throws -> Response {
        try await requests.sendJSON(path: path, method: "POST", body: body)
    }

    private func status(path: String, body: some Encodable) async throws -> Bool {
        let response: StatusResponse = try await post(path, body: body)
        guard let status = response.status else {
            throw BetterAuthError.invalidResponse
        }
        return status
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
