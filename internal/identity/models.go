package identity

import (
	"time"

	"github.com/google/uuid"
)

// User is a person the application has seen. Almost always that is a døckio
// account, linked through an OIDCIdentity; the exception is a local break-glass
// superuser, the only kind of user with a password.
//
// Name and email are COPIES of what døckio said at the last sign-in. They are for
// display and for audit metadata. Nothing is ever looked up by them.
type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email,omitempty"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`

	// IsSuperuser marks a LOCAL break-glass account: created from the CLI, signed
	// in on an unlinked page with a password, and able to enter every
	// organization (audited). It exists for first-run setup and for renewing a
	// dead døckio connection -- the two moments døckio cannot let anyone in.
	IsSuperuser bool `json:"is_superuser"`

	// IsActive is the application's own kill switch, on top of whatever døckio
	// says. Deactivating revokes every session at once.
	IsActive bool `json:"is_active"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	PasswordHash string `json:"-"`
}

// OIDCIdentity links a user to a døckio account.
//
// The link is (Issuer, UID). Not sub, which is the username and can be renamed;
// not email, which two accounts can share and one can lack.
type OIDCIdentity struct {
	ID       uuid.UUID `json:"id"`
	UserID   uuid.UUID `json:"user_id"`
	Issuer   string    `json:"issuer"`
	UID      string    `json:"uid"`
	Username string    `json:"username"`
}

// Organization is a tenant. Its people, roles and groups live in its døckio realm.
type Organization struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`

	// DockioRealm is the døckio realm that holds this organization's members.
	// Nil until one is assigned; until then only a superuser can enter.
	DockioRealm *string `json:"dockio_realm"`

	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsDeleted reports whether the organization has been soft-deleted.
func (t Organization) IsDeleted() bool { return t.DeletedAt != nil }

// realm returns the organization's realm, or "".
func (t Organization) realm() string {
	if t.DockioRealm == nil {
		return ""
	}
	return *t.DockioRealm
}

// OrganizationAccess is the caller's authority in one organization, resolved once
// per request by the server's requireOrganization middleware.
type OrganizationAccess struct {
	Organization Organization `json:"organization"`

	// Permissions are what the caller may do here: døckio's effective keys for
	// them in the organization's realm, mapped back onto this application's
	// catalog -- or the frozen scope of an API key.
	Permissions PermissionSet `json:"permissions"`

	// ViaSuperuser marks entry through the superuser bypass (a local superuser,
	// or a døckio account holding system.superuser). Every such access is audited.
	ViaSuperuser bool `json:"via_superuser,omitempty"`
	// ViaAPIKey marks a request authenticated with an API key.
	ViaAPIKey bool `json:"via_api_key,omitempty"`
}

// Can reports whether the caller holds p here.
func (a OrganizationAccess) Can(p Permission) bool {
	return a.Permissions.Has(p)
}

// Session is a server-side session. The browser holds only an opaque token naming
// it -- never a døckio token.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	UserAgent  string     `json:"user_agent"`
	IPAddress  string     `json:"ip_address,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	// AuthMethod is "dockio" or "password" (the local superuser).
	AuthMethod string `json:"auth_method"`
	// DockioRealms are the realms døckio said the person belongs to at sign-in.
	// They decide which organizations the person is OFFERED; whether they may
	// still ENTER one is asked of døckio on every request (see access.go).
	DockioRealms []string `json:"dockio_realms,omitempty"`

	DockioUID  string `json:"-"`
	DockioSID  string `json:"-"`
	IDTokenEnc []byte `json:"-"`
	TokenHash  []byte `json:"-"`
}

// Session authentication methods.
const (
	AuthMethodDockio   = "dockio"
	AuthMethodPassword = "password"
)

// APIKey is a programmatic credential for one organization. It carries its own,
// frozen permission scope, taken from the same catalog døckio's roles use.
type APIKey struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	// TokenPrefix is the first few characters of the token, kept so a human can
	// tell their keys apart. The token itself is shown once and stored hashed.
	TokenPrefix string        `json:"token_prefix"`
	Permissions PermissionSet `json:"permissions"`
	CreatedBy   uuid.UUID     `json:"created_by"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time    `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
}
