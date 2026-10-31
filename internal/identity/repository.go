package identity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
)

// Repository is the only code in the application that writes SQL for identity
// tables.
//
// THE ORGANIZATION-SCOPING RULE: every method that touches an organization-owned
// table takes organizationID as a parameter and puts it in the WHERE clause --
// even when the row's primary key would already be unique. Filtering by id alone
// is what turns a guessed UUID into a cross-organization read.
type Repository struct {
	db database.DB
}

// NewRepository returns a Repository backed by db, which may be a *pgxpool.Pool
// or a pgx.Tx. Passing a transaction is how a caller makes several repository
// calls atomic.
func NewRepository(db database.DB) *Repository {
	return &Repository{db: db}
}

// sessionTouchInterval throttles writes to sessions.last_used_at: accurate enough
// for "last active a few minutes ago", without rewriting a row on every request.
const sessionTouchInterval = `interval '5 minutes'`

// ---------------------------------------------------------------- users

const userColumns = `id, email, password_hash, first_name, last_name, is_superuser, is_active, created_at, updated_at`

const qualifiedUserColumns = `users.id, users.email, users.password_hash, users.first_name, users.last_name,
	users.is_superuser, users.is_active, users.created_at, users.updated_at`

// CreateSuperuser inserts a local break-glass account.
func (r *Repository) CreateSuperuser(ctx context.Context, email, passwordHash, firstName, lastName string) (User, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, first_name, last_name, is_superuser)
		 VALUES ($1, $2, $3, $4, true)
		 RETURNING `+userColumns,
		email, passwordHash, firstName, lastName,
	)
	u, err := scanUser(row)
	if isUniqueViolation(err, "users_superuser_email_idx") {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: create superuser: %w", err)
	}
	return u, nil
}

// GetSuperuserByEmail finds a local superuser for the emergency sign-in. It is
// the ONLY lookup by email in the application, and it only ever matches a
// superuser: a døckio account's email is a copy, not a key.
func (r *Repository) GetSuperuserByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1 AND is_superuser`, email)
	return scanUserOrNotFound(row, "get superuser by email")
}

// SetSuperuserPassword replaces a superuser's password.
func (r *Repository) SetSuperuserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1 AND is_superuser`,
		userID, passwordHash,
	)
	if err != nil {
		return fmt.Errorf("identity: set superuser password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSuperuser removes a local superuser. Their audit entries survive,
// anonymised (audit_log.actor_user_id is ON DELETE SET NULL).
func (r *Repository) DeleteSuperuser(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRow(ctx,
		`DELETE FROM users WHERE email = $1 AND is_superuser RETURNING `+userColumns, email)
	return scanUserOrNotFound(row, "delete superuser")
}

// CreateUser inserts the local row for a døckio account seen for the first time.
func (r *Repository) CreateUser(ctx context.Context, email, firstName, lastName string) (User, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO users (email, first_name, last_name) VALUES ($1, $2, $3) RETURNING `+userColumns,
		nullIfEmpty(email), firstName, lastName,
	)
	u, err := scanUser(row)
	if err != nil {
		return User{}, fmt.Errorf("identity: create user: %w", err)
	}
	return u, nil
}

// RefreshUser updates the copies of what døckio said about a person.
func (r *Repository) RefreshUser(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET email = $2, first_name = $3, last_name = $4, updated_at = now()
		 WHERE id = $1 AND NOT is_superuser
		 RETURNING `+userColumns,
		id, nullIfEmpty(email), firstName, lastName,
	)
	return scanUserOrNotFound(row, "refresh user")
}

// GetUserByID looks a user up by primary key.
func (r *Repository) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return scanUserOrNotFound(row, "get user by id")
}

// SetUserActive activates or deactivates a user. Deactivation alone does not end
// their sessions; Service.SetUserActive revokes them in the same transaction.
func (r *Repository) SetUserActive(ctx context.Context, userID uuid.UUID, isActive bool) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET is_active = $2, updated_at = now() WHERE id = $1 RETURNING `+userColumns,
		userID, isActive,
	)
	return scanUserOrNotFound(row, "set user active")
}

// ListAllUsers returns every user, newest first, with keyset pagination on the
// uuidv7 primary key. There is no organization filter here: the route that
// reaches it requires system.users.
func (r *Repository) ListAllUsers(ctx context.Context, before uuid.UUID, limit int) ([]User, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var beforeArg any
	if before != uuid.Nil {
		beforeArg = before
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+userColumns+` FROM users
		 WHERE ($1::uuid IS NULL OR id < $1::uuid)
		 ORDER BY id DESC LIMIT $2`,
		beforeArg, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list users: %w", err)
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- døckio identities

const identityColumns = `id, user_id, issuer, uid, username`

// GetIdentity finds the link for a døckio account.
func (r *Repository) GetIdentity(ctx context.Context, issuer, uid string) (OIDCIdentity, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+identityColumns+` FROM oidc_identities WHERE issuer = $1 AND uid = $2`, issuer, uid)
	return scanIdentityOrNotFound(row)
}

// GetIdentityForUser finds a user's link under one issuer.
func (r *Repository) GetIdentityForUser(ctx context.Context, userID uuid.UUID, issuer string) (OIDCIdentity, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+identityColumns+` FROM oidc_identities WHERE user_id = $1 AND issuer = $2`, userID, issuer)
	return scanIdentityOrNotFound(row)
}

// CreateIdentity links a user to a døckio account.
func (r *Repository) CreateIdentity(ctx context.Context, userID uuid.UUID, issuer, uid, username string) (OIDCIdentity, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO oidc_identities (user_id, issuer, uid, username)
		 VALUES ($1, $2, $3, $4) RETURNING `+identityColumns,
		userID, issuer, uid, username,
	)
	i, err := scanIdentity(row)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("identity: create oidc identity: %w", err)
	}
	return i, nil
}

// SetIdentityUsername records a renamed username. The link itself never moves.
func (r *Repository) SetIdentityUsername(ctx context.Context, id uuid.UUID, username string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE oidc_identities SET username = $2, updated_at = now() WHERE id = $1 AND username <> $2`,
		id, username)
	if err != nil {
		return fmt.Errorf("identity: set username: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- organizations

const organizationColumns = `id, slug, name, dockio_realm, deleted_at, created_at, updated_at`

// liveOrganization is the predicate for "not soft-deleted". Every read of an
// organization the caller might act on includes it.
const liveOrganization = `deleted_at IS NULL`

// CreateOrganization inserts an organization.
func (r *Repository) CreateOrganization(ctx context.Context, slug, name string, realm *string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO organizations (slug, name, dockio_realm) VALUES ($1, $2, $3) RETURNING `+organizationColumns,
		slug, name, realm,
	)
	t, err := scanOrganization(row)
	switch {
	case isUniqueViolation(err, "organizations_live_slug_idx"):
		return Organization{}, ErrSlugTaken
	case isUniqueViolation(err, "organizations_dockio_realm_idx"):
		return Organization{}, ErrRealmTaken
	case err != nil:
		return Organization{}, fmt.Errorf("identity: create organization: %w", err)
	}
	return t, nil
}

// SetOrganizationRealm links (or, with nil, unlinks) a live organization to a realm.
func (r *Repository) SetOrganizationRealm(ctx context.Context, organizationID uuid.UUID, realm *string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE organizations SET dockio_realm = $2, updated_at = now()
		 WHERE id = $1 AND `+liveOrganization+` RETURNING `+organizationColumns,
		organizationID, realm,
	)
	t, err := scanOrganization(row)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Organization{}, ErrNotFound
	case isUniqueViolation(err, "organizations_dockio_realm_idx"):
		return Organization{}, ErrRealmTaken
	case err != nil:
		return Organization{}, fmt.Errorf("identity: set organization realm: %w", err)
	}
	return t, nil
}

// GetOrganizationBySlug finds a live organization.
func (r *Repository) GetOrganizationBySlug(ctx context.Context, slug string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+organizationColumns+` FROM organizations WHERE slug = $1 AND `+liveOrganization, slug)
	return scanOrganizationOrNotFound(row, "get organization by slug")
}

// GetOrganizationByID finds a live organization.
func (r *Repository) GetOrganizationByID(ctx context.Context, id uuid.UUID) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+organizationColumns+` FROM organizations WHERE id = $1 AND `+liveOrganization, id)
	return scanOrganizationOrNotFound(row, "get organization by id")
}

// ListOrganizationsInRealms returns the live organizations linked to any of realms.
func (r *Repository) ListOrganizationsInRealms(ctx context.Context, realms []string) ([]Organization, error) {
	if len(realms) == 0 {
		return []Organization{}, nil
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+organizationColumns+` FROM organizations
		 WHERE dockio_realm = ANY($1) AND `+liveOrganization+` ORDER BY name`,
		realms,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list organizations in realms: %w", err)
	}
	return collectOrganizations(rows)
}

// ListAllOrganizations returns every organization, deleted ones included, newest
// first. System surface only.
func (r *Repository) ListAllOrganizations(ctx context.Context, before uuid.UUID, limit int) ([]Organization, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var beforeArg any
	if before != uuid.Nil {
		beforeArg = before
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+organizationColumns+` FROM organizations
		 WHERE ($1::uuid IS NULL OR id < $1::uuid)
		 ORDER BY id DESC LIMIT $2`,
		beforeArg, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list all organizations: %w", err)
	}
	return collectOrganizations(rows)
}

// CountOrganizationsWithRealm counts live organizations linked to any realm. A
// tenant switch is refused while this is non-zero: those realms live in the
// current tenant, and switching would strand their people.
func (r *Repository) CountOrganizationsWithRealm(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM organizations WHERE dockio_realm IS NOT NULL AND `+liveOrganization).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("identity: count linked organizations: %w", err)
	}
	return n, nil
}

// UpdateOrganization renames a live organization.
func (r *Repository) UpdateOrganization(ctx context.Context, organizationID uuid.UUID, name string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE organizations SET name = $2, updated_at = now()
		 WHERE id = $1 AND `+liveOrganization+` RETURNING `+organizationColumns,
		organizationID, name,
	)
	return scanOrganizationOrNotFound(row, "update organization")
}

// SoftDeleteOrganization hides an organization from everyone at once. Nothing is
// destroyed; a superuser can restore it.
func (r *Repository) SoftDeleteOrganization(ctx context.Context, organizationID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE organizations SET deleted_at = now(), updated_at = now() WHERE id = $1 AND `+liveOrganization,
		organizationID,
	)
	if err != nil {
		return fmt.Errorf("identity: soft delete organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RestoreOrganization brings a soft-deleted organization back under slug (its
// old slug may have been taken in the meantime).
func (r *Repository) RestoreOrganization(ctx context.Context, organizationID uuid.UUID, slug string) (Organization, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE organizations SET deleted_at = NULL, slug = $2, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NOT NULL RETURNING `+organizationColumns,
		organizationID, slug,
	)
	t, err := scanOrganization(row)
	switch {
	case isUniqueViolation(err, "organizations_live_slug_idx"):
		return Organization{}, ErrSlugTaken
	case isUniqueViolation(err, "organizations_dockio_realm_idx"):
		return Organization{}, ErrRealmTaken
	case errors.Is(err, pgx.ErrNoRows):
		return Organization{}, ErrNotFound
	case err != nil:
		return Organization{}, fmt.Errorf("identity: restore organization: %w", err)
	}
	return t, nil
}

// PurgeDeletedOrganizations destroys organizations soft-deleted longer than
// retain ago, cascading away every row they own.
func (r *Repository) PurgeDeletedOrganizations(ctx context.Context, retain time.Duration) (int64, error) {
	if retain <= 0 {
		return 0, nil
	}
	tag, err := r.db.Exec(ctx,
		`DELETE FROM organizations
		 WHERE deleted_at IS NOT NULL AND deleted_at < now() - make_interval(secs => $1)`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: purge deleted organizations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- sessions

const sessionColumns = `id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at,
	auth_method, dockio_uid, dockio_sid, dockio_realms, id_token_enc`

// NewSession is what CreateSession stores.
type NewSession struct {
	UserID       uuid.UUID
	TokenHash    []byte
	ExpiresAt    time.Time
	UserAgent    string
	IPAddress    string
	AuthMethod   string
	DockioUID    string
	DockioSID    string
	DockioRealms []string
	IDTokenEnc   []byte
}

// CreateSession stores a session. The token itself is never stored, only its hash.
func (r *Repository) CreateSession(ctx context.Context, n NewSession) (Session, error) {
	if n.DockioRealms == nil {
		n.DockioRealms = []string{}
	}
	row := r.db.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at, user_agent, ip_address,
		                       auth_method, dockio_uid, dockio_sid, dockio_realms, id_token_enc)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING `+sessionColumns,
		n.UserID, n.TokenHash, n.ExpiresAt, n.UserAgent, parseIP(n.IPAddress),
		n.AuthMethod, nullIfEmpty(n.DockioUID), nullIfEmpty(n.DockioSID), n.DockioRealms, n.IDTokenEnc,
	)
	s, err := scanSession(row)
	if err != nil {
		return Session{}, fmt.Errorf("identity: create session: %w", err)
	}
	s.TokenHash = n.TokenHash
	return s, nil
}

// AuthenticateSession resolves a session token hash to its user in one round
// trip. A session is usable only if unrevoked, unexpired and owned by an active
// user; all three are in the WHERE clause so no caller can forget one.
func (r *Repository) AuthenticateSession(ctx context.Context, tokenHash []byte) (User, Session, error) {
	row := r.db.QueryRow(ctx,
		`WITH live AS (
		     SELECT `+sessionColumns+` FROM sessions
		     WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		 ), touched AS (
		     UPDATE sessions SET last_used_at = now()
		     WHERE sessions.id IN (SELECT live.id FROM live)
		       AND (sessions.last_used_at IS NULL
		            OR sessions.last_used_at < now() - `+sessionTouchInterval+`)
		 )
		 SELECT `+qualifiedUserColumns+`,
		        live.id, live.user_id, live.expires_at, live.revoked_at, live.user_agent, live.ip_address,
		        live.last_used_at, live.created_at, live.auth_method, live.dockio_uid, live.dockio_sid,
		        live.dockio_realms, live.id_token_enc
		 FROM live JOIN users ON users.id = live.user_id
		 WHERE users.is_active`,
		tokenHash,
	)

	var u User
	var email, hash *string
	var s Session
	var ip *netip.Addr
	var uid, sid *string
	err := row.Scan(
		&u.ID, &email, &hash, &u.FirstName, &u.LastName, &u.IsSuperuser, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
		&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
		&s.AuthMethod, &uid, &sid, &s.DockioRealms, &s.IDTokenEnc,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, Session{}, ErrUnauthenticated
	}
	if err != nil {
		return User{}, Session{}, fmt.Errorf("identity: authenticate session: %w", err)
	}
	u.Email, u.PasswordHash = deref(email), deref(hash)
	s.DockioUID, s.DockioSID = deref(uid), deref(sid)
	if ip != nil {
		s.IPAddress = ip.String()
	}
	s.TokenHash = tokenHash
	return u, s, nil
}

// RevokeSession marks one session dead. Idempotent: sign-out always succeeds.
func (r *Repository) RevokeSession(ctx context.Context, tokenHash []byte) error {
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash)
	if err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	return nil
}

// RevokeSessionByID kills ONE of a user's sessions. The user id is in the WHERE
// clause, so nobody can revoke somebody else's session by guessing its id.
func (r *Repository) RevokeSessionByID(ctx context.Context, userID, sessionID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		sessionID, userID,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke session by id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeUserSessions kills every live session a user has.
func (r *Repository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeDockioSessions ends the sessions a back-channel logout names: one døckio
// session (sid) when given, otherwise every session of the døckio account (uid).
func (r *Repository) RevokeDockioSessions(ctx context.Context, uid, sid string) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE revoked_at IS NULL AND auth_method = 'dockio'
		   AND (($2 <> '' AND dockio_sid = $2) OR ($2 = '' AND $1 <> '' AND dockio_uid = $1))`,
		uid, sid,
	)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke døckio sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DropRealmFromSessions handles a realm-scoped logout: the person stays signed in,
// but is no longer offered that realm's organizations.
func (r *Repository) DropRealmFromSessions(ctx context.Context, uid, realm string) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET dockio_realms = array_remove(dockio_realms, $2)
		 WHERE revoked_at IS NULL AND dockio_uid = $1 AND $2 = ANY(dockio_realms)`,
		uid, realm,
	)
	if err != nil {
		return 0, fmt.Errorf("identity: drop realm from sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListUserSessions returns a user's live sessions, newest first.
func (r *Repository) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+sessionColumns+` FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY id DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list sessions: %w", err)
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan session: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteDeadSessions removes sessions that expired or were revoked more than
// retain ago. Sessions are the one table here that grows without bound.
func (r *Repository) DeleteDeadSessions(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM sessions
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (revoked_at IS NOT NULL AND revoked_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- scanning

type row interface {
	Scan(dest ...any) error
}

func scanUser(r row) (User, error) {
	var u User
	var email, hash *string
	err := r.Scan(&u.ID, &email, &hash, &u.FirstName, &u.LastName, &u.IsSuperuser, &u.IsActive,
		&u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	u.Email, u.PasswordHash = deref(email), deref(hash)
	return u, nil
}

func scanUserOrNotFound(r row, op string) (User, error) {
	u, err := scanUser(r)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: %s: %w", op, err)
	}
	return u, nil
}

func scanIdentity(r row) (OIDCIdentity, error) {
	var i OIDCIdentity
	err := r.Scan(&i.ID, &i.UserID, &i.Issuer, &i.UID, &i.Username)
	return i, err
}

func scanIdentityOrNotFound(r row) (OIDCIdentity, error) {
	i, err := scanIdentity(r)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCIdentity{}, ErrNotFound
	}
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("identity: get oidc identity: %w", err)
	}
	return i, nil
}

func scanOrganization(r row) (Organization, error) {
	var t Organization
	err := r.Scan(&t.ID, &t.Slug, &t.Name, &t.DockioRealm, &t.DeletedAt, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func scanOrganizationOrNotFound(r row, op string) (Organization, error) {
	t, err := scanOrganization(r)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("identity: %s: %w", op, err)
	}
	return t, nil
}

func collectOrganizations(rows pgx.Rows) ([]Organization, error) {
	defer rows.Close()
	out := []Organization{}
	for rows.Next() {
		t, err := scanOrganization(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan organization: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanSession(r row) (Session, error) {
	var s Session
	var ip *netip.Addr
	var uid, sid *string
	err := r.Scan(&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
		&s.AuthMethod, &uid, &sid, &s.DockioRealms, &s.IDTokenEnc)
	if err != nil {
		return Session{}, err
	}
	if ip != nil {
		s.IPAddress = ip.String()
	}
	s.DockioUID, s.DockioSID = deref(uid), deref(sid)
	return s, nil
}

// ---------------------------------------------------------------- helpers

// parseIP converts a client IP into what pgx encodes into an inet column, or nil.
// A malformed address becomes NULL: nobody is refused because a proxy sent a
// header we could not parse.
func parseIP(s string) *netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}

// isUniqueViolation reports a unique-constraint failure on the NAMED constraint,
// so a second unique index on a table can never turn into the wrong error.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// isForeignKeyViolation reports a referential-integrity failure on the named
// constraint -- both 23503 (inserting a dangling reference) and 23001 (deleting
// a row an ON DELETE RESTRICT reference still points at).
func isForeignKeyViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return (pgErr.Code == "23503" || pgErr.Code == "23001") && pgErr.ConstraintName == constraint
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
