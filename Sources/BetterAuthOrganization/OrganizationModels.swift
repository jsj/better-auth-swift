import Foundation

public struct Organization: Codable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let slug: String
    public let logo: String?
    public let metadata: [String: String]?
    public let createdAt: Date

    public init(id: String,
                name: String,
                slug: String,
                logo: String? = nil,
                metadata: [String: String]? = nil,
                createdAt: Date = Date())
    {
        self.id = id
        self.name = name
        self.slug = slug
        self.logo = logo
        self.metadata = metadata
        self.createdAt = createdAt
    }
}

public struct OrganizationMember: Codable, Sendable, Equatable {
    public let id: String
    public let organizationId: String
    public let userId: String
    public let role: String
    public let createdAt: Date
    public let user: MemberUser?

    public init(id: String,
                organizationId: String,
                userId: String,
                role: String,
                createdAt: Date = Date(),
                user: MemberUser? = nil)
    {
        self.id = id
        self.organizationId = organizationId
        self.userId = userId
        self.role = role
        self.createdAt = createdAt
        self.user = user
    }

    public struct MemberUser: Codable, Sendable, Equatable {
        public let id: String
        public let email: String
        public let name: String
        public let image: String?

        public init(id: String, email: String, name: String, image: String? = nil) {
            self.id = id
            self.email = email
            self.name = name
            self.image = image
        }
    }
}

public struct OrganizationInvitation: Codable, Sendable, Equatable {
    public let id: String
    public let organizationId: String
    public let email: String
    public let role: String
    public let status: String
    public let inviterId: String
    public let expiresAt: Date
    public let createdAt: Date

    public init(id: String,
                organizationId: String,
                email: String,
                role: String,
                status: String = "pending",
                inviterId: String,
                expiresAt: Date,
                createdAt: Date = Date())
    {
        self.id = id
        self.organizationId = organizationId
        self.email = email
        self.role = role
        self.status = status
        self.inviterId = inviterId
        self.expiresAt = expiresAt
        self.createdAt = createdAt
    }
}

// MARK: - Requests

public struct CreateOrganizationRequest: Codable, Sendable, Equatable {
    public let name: String
    public let slug: String
    public let logo: String?
    public let metadata: [String: String]?

    public init(name: String, slug: String, logo: String? = nil, metadata: [String: String]? = nil) {
        self.name = name
        self.slug = slug
        self.logo = logo
        self.metadata = metadata
    }
}

public struct UpdateOrganizationRequest: Codable, Sendable, Equatable {
    public let organizationId: String
    public let name: String?
    public let slug: String?
    public let logo: String?
    public let metadata: [String: String]?

    public init(organizationId: String, name: String? = nil, slug: String? = nil,
                logo: String? = nil, metadata: [String: String]? = nil)
    {
        self.organizationId = organizationId
        self.name = name
        self.slug = slug
        self.logo = logo
        self.metadata = metadata
    }
}

public struct InviteMemberRequest: Codable, Sendable, Equatable {
    public let organizationId: String
    public let email: String
    public let role: String

    public init(organizationId: String, email: String, role: String = "member") {
        self.organizationId = organizationId
        self.email = email
        self.role = role
    }
}

public struct UpdateMemberRoleRequest: Codable, Sendable, Equatable {
    public let organizationId: String
    public let memberId: String
    public let role: String

    public init(organizationId: String, memberId: String, role: String) {
        self.organizationId = organizationId
        self.memberId = memberId
        self.role = role
    }
}

public struct RemoveMemberRequest: Codable, Sendable, Equatable {
    public let organizationId: String
    public let memberIdOrEmail: String

    public init(organizationId: String, memberIdOrEmail: String) {
        self.organizationId = organizationId
        self.memberIdOrEmail = memberIdOrEmail
    }
}

// MARK: - Responses

struct FullOrganizationResponse: Codable, Sendable {
    let id: String
    let name: String
    let slug: String
    let logo: String?
    let metadata: [String: String]?
    let createdAt: Date
    let members: [OrganizationMember]
    let invitations: [OrganizationInvitation]

    var organization: Organization {
        Organization(id: id, name: name, slug: slug, logo: logo, metadata: metadata, createdAt: createdAt)
    }
}

struct StatusResponse: Codable, Sendable {
    let status: Bool?
    let message: String?
}
