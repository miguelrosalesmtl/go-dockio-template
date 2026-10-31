package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/auth"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/secrets"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/settings"
)

// Service holds the identity rules: what must be validated, what must happen
// atomically, what must be audited, and what must be asked of døckio. HTTP
// handlers call it and do nothing else of consequence.
//
// The work is split by concern across files:
//
//	service.go     sessions, the local superuser, organizations, users
//	connection.go  the døckio connection: Quick connect, renew, revoke, disconnect
//	signin.go      sign-in and sign-out through døckio, back-channel logout
//	access.go      what a caller may do: døckio's effective permissions, cached
type Service struct {
	pool   *pgxpool.Pool
	repo   *Repository
	hasher *auth.Hasher
	box    *secrets.Box
	http   *http.Client
	log    *slog.Logger
	now    func() time.Time

	auth     settings.Auth
	dk       settings.Dockio
	frontend settings.Frontend

	// rp is the døckio client built from the stored connection, rebuilt whenever
	// the connection changes. See client().
	rpMu  sync.Mutex
	rp    *dockio.Client
	rpKey string

	effective effectiveCache
}

// Config is what a Service is built from.
type Config struct {
	Auth     settings.Auth
	Dockio   settings.Dockio
	Frontend settings.Frontend
	Secrets  *secrets.Box
	Log      *slog.Logger
	// HTTP is used for every call to døckio. Nil: dockio.NewHTTPClient(), which
	// never follows redirects.
	HTTP *http.Client
}

// NewService builds the identity service.
func NewService(pool *pgxpool.Pool, cfg Config) *Service {
	if cfg.HTTP == nil {
		cfg.HTTP = dockio.NewHTTPClient()
	}
	return &Service{
		pool:      pool,
		repo:      NewRepository(pool),
		hasher:    auth.NewHasher(cfg.Auth.ArgonMemoryKiB, cfg.Auth.ArgonIterations, cfg.Auth.ArgonParallelism),
		box:       cfg.Secrets,
		http:      cfg.HTTP,
		log:       cfg.Log,
		now:       time.Now,
		auth:      cfg.Auth,
		dk:        cfg.Dockio,
		frontend:  cfg.Frontend,
		effective: effectiveCache{entries: map[string]effectiveEntry{}},
	}
}

// RequestMeta is what the service records about the caller of a request.
type RequestMeta struct {
	UserAgent string
	IPAddress string
}

// ---------------------------------------------------------------- sessions

// newSession mints a session token and stores its hash. The plaintext is the only
// copy outside the client.
func (s *Service) newSession(ctx context.Context, db database.DB, n NewSession) (string, error) {
	plaintext, digest, err := auth.NewToken(auth.SessionTokenPrefix)
	if err != nil {
		return "", err
	}
	n.TokenHash = digest
	n.ExpiresAt = s.now().Add(s.auth.SessionTTL)
	_, err = NewRepository(db).CreateSession(ctx, n)
	return plaintext, err
}

// Authenticate resolves a session token to its user. It runs on every
// authenticated request, so it is one indexed query.
func (s *Service) Authenticate(ctx context.Context, token string) (User, Session, error) {
	if token == "" {
		return User{}, Session{}, ErrUnauthenticated
	}
	return s.repo.AuthenticateSession(ctx, auth.HashToken(token))
}

// ListSessions returns the caller's live sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	return s.repo.ListUserSessions(ctx, userID)
}

// RevokeSession ends one of the caller's own sessions: "sign out that device".
func (s *Service) RevokeSession(ctx context.Context, actor User, sessionID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSessionByID(ctx, actor.ID, sessionID); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: audit.ActionSessionRevoked,
			TargetType: "session", TargetID: sessionID.String(),
		})
	})
}

// CleanupSessions prunes dead sessions and expired sign-in and connect attempts.
func (s *Service) CleanupSessions(ctx context.Context, retain time.Duration) (int64, error) {
	n, err := s.repo.DeleteDeadSessions(ctx, retain)
	if err != nil {
		return n, err
	}
	m, err := s.repo.DeleteExpiredAttempts(ctx)
	return n + m, err
}

// ---------------------------------------------------------------- the local superuser

// SuperuserSignIn is the emergency way in: a local superuser's email and password,
// on a page nothing links to. It exists because døckio cannot let anybody in
// before the application is connected, nor after the connection has died -- and
// somebody has to be able to connect or renew it.
//
// Every failure looks the same to the caller (and takes as long), so the page
// cannot be used to find out which emails are superusers. The audit log records
// which failure it really was.
func (s *Service) SuperuserSignIn(ctx context.Context, email, password string, meta RequestMeta) (string, User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.GetSuperuserByEmail(ctx, email)
	if err != nil {
		if isNotFound(err) {
			_, _ = s.hasher.Hash(password) // same cost as a real check
			s.recordFailedLogin(ctx, nil, map[string]any{"email": email, "reason": "unknown_email"})
			return "", User{}, ErrInvalidCredentials
		}
		return "", User{}, err
	}
	if !user.IsActive {
		_, _ = s.hasher.Hash(password)
		s.recordFailedLogin(ctx, &user.ID, map[string]any{"email": email, "reason": "deactivated"})
		return "", User{}, ErrInvalidCredentials
	}
	if err := s.hasher.Verify(password, user.PasswordHash); err != nil {
		reason := "wrong_password"
		if !errors.Is(err, auth.ErrMismatch) {
			reason = "corrupt_hash"
			s.log.Error("stored password hash is unreadable", slog.String("user_id", user.ID.String()))
		}
		s.recordFailedLogin(ctx, &user.ID, map[string]any{"email": email, "reason": reason})
		return "", User{}, ErrInvalidCredentials
	}
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if newHash, err := s.hasher.Hash(password); err == nil {
			_ = s.repo.SetSuperuserPassword(ctx, user.ID, newHash)
		}
	}

	var token string
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		var err error
		token, err = s.newSession(ctx, db, NewSession{
			UserID: user.ID, UserAgent: meta.UserAgent, IPAddress: meta.IPAddress, AuthMethod: AuthMethodPassword,
		})
		if err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID, Action: audit.ActionUserSignedIn, TargetType: "user", TargetID: user.ID.String(),
			Metadata: map[string]any{"method": AuthMethodPassword, "ip": meta.IPAddress, "user_agent": meta.UserAgent},
		})
	})
	if err != nil {
		return "", User{}, err
	}
	return token, user, nil
}

// recordFailedLogin audits a refused sign-in. It is written on the pool and a
// failure is logged, not returned: losing one entry is bad, but turning a clean
// refusal into a 500 because the audit table hiccuped is worse.
func (s *Service) recordFailedLogin(ctx context.Context, userID *uuid.UUID, metadata map[string]any) {
	err := audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		ActorUserID: userID, Action: audit.ActionLoginFailed, TargetType: "user", Metadata: metadata,
	})
	if err != nil {
		s.log.Error("could not audit a failed sign-in", slog.String("error", err.Error()))
	}
}

// CreateSuperuser creates a local superuser, or sets a new password on an
// existing one. It is reachable only from the CLI: acquiring the one credential
// that bypasses døckio takes shell access to the server, not a stolen session.
func (s *Service) CreateSuperuser(ctx context.Context, email, password string) (User, bool, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, false, err
	}
	if err := s.validatePassword(password); err != nil {
		return User{}, false, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, false, err
	}

	var user User
	created := false
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		existing, err := repo.GetSuperuserByEmail(ctx, email)
		switch {
		case err == nil:
			user = existing
			if err := repo.SetSuperuserPassword(ctx, existing.ID, hash); err != nil {
				return err
			}
			// Every session on the old password ends: whoever set a new one
			// may be doing so precisely because the old one leaked.
			if _, err := repo.RevokeUserSessions(ctx, existing.ID); err != nil {
				return err
			}
			return audit.NewRecorder(db).Record(ctx, audit.Event{
				Action: audit.ActionSuperuserPasswordSet, TargetType: "user", TargetID: existing.ID.String(),
				Metadata: map[string]any{"email": email, "via": "cli"},
			})
		case isNotFound(err):
			user, err = repo.CreateSuperuser(ctx, email, hash, "", "")
			if err != nil {
				return err
			}
			created = true
			return audit.NewRecorder(db).Record(ctx, audit.Event{
				Action: audit.ActionSuperuserCreated, TargetType: "user", TargetID: user.ID.String(),
				Metadata: map[string]any{"email": email, "via": "cli"},
			})
		default:
			return err
		}
	})
	return user, created, err
}

// DeleteSuperuser removes a local superuser. CLI only.
func (s *Service) DeleteSuperuser(ctx context.Context, email string) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		var err error
		if user, err = NewRepository(db).DeleteSuperuser(ctx, email); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			Action: audit.ActionSuperuserDeleted, TargetType: "user", TargetID: user.ID.String(),
			Metadata: map[string]any{"email": email, "via": "cli"},
		})
	})
	return user, err
}

// ---------------------------------------------------------------- organizations

// CreateOrganization creates an organization, optionally already linked to the
// døckio realm that will hold its people. System surface only.
//
// Creating the realm itself in døckio is not done here: that is døckio's
// provisioning API (SOIDC §12-13), which this template does not implement yet.
// Until it does, create the realm in døckio's console and link it.
func (s *Service) CreateOrganization(ctx context.Context, actor User, slug, name, realm string) (Organization, error) {
	slug, err := normalizeSlug(slug)
	if err != nil {
		return Organization{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return Organization{}, invalid("organization name is required, at most 200 characters")
	}
	realmPtr, err := normalizeRealm(realm)
	if err != nil {
		return Organization{}, err
	}

	var org Organization
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		org, err = NewRepository(db).CreateOrganization(ctx, slug, name, realmPtr)
		if err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &org.ID, ActorUserID: &actor.ID, Action: audit.ActionOrganizationCreated,
			TargetType: "organization", TargetID: org.ID.String(),
			Metadata: map[string]any{"slug": slug, "name": name, "dockio_realm": realm},
		})
	})
	return org, err
}

// SetOrganizationRealm links an organization to a døckio realm, or unlinks it
// with "". Whoever is in that realm can now enter the organization -- so this is
// a system action, and audited with the before and after.
func (s *Service) SetOrganizationRealm(ctx context.Context, actor User, organizationID uuid.UUID, realm string) (Organization, error) {
	realmPtr, err := normalizeRealm(realm)
	if err != nil {
		return Organization{}, err
	}
	var org Organization
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		before, err := repo.GetOrganizationByID(ctx, organizationID)
		if err != nil {
			return err
		}
		if org, err = repo.SetOrganizationRealm(ctx, organizationID, realmPtr); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &org.ID, ActorUserID: &actor.ID, Action: audit.ActionOrganizationRealmChanged,
			TargetType: "organization", TargetID: org.ID.String(),
			Metadata: map[string]any{"from": before.realm(), "to": realm},
		})
	})
	if err == nil {
		s.effective.clear() // answers cached for the old realm no longer apply
	}
	return org, err
}

// ListOrganizations returns the organizations a session is offered: those linked
// to a realm døckio said the person is in at sign-in. A local superuser is
// offered none here -- they work from the system surface.
func (s *Service) ListOrganizations(ctx context.Context, session Session) ([]Organization, error) {
	return s.repo.ListOrganizationsInRealms(ctx, session.DockioRealms)
}

// UpdateOrganization renames an organization.
func (s *Service) UpdateOrganization(ctx context.Context, actor User, access OrganizationAccess, name string) (Organization, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return Organization{}, invalid("organization name is required, at most 200 characters")
	}
	var org Organization
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		var err error
		if org, err = NewRepository(db).UpdateOrganization(ctx, access.Organization.ID, name); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID, ActorUserID: &actor.ID, Action: audit.ActionOrganizationUpdated,
			TargetType: "organization", TargetID: access.Organization.ID.String(),
			Metadata: map[string]any{"from": access.Organization.Name, "to": name},
		})
	})
	return org, err
}

// DeleteOrganization soft-deletes an organization: invisible to everyone at once,
// nothing destroyed, restorable from the system surface. Its slug is released.
func (s *Service) DeleteOrganization(ctx context.Context, actor User, access OrganizationAccess) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).SoftDeleteOrganization(ctx, access.Organization.ID); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &access.Organization.ID, ActorUserID: &actor.ID, Action: audit.ActionOrganizationDeleted,
			TargetType: "organization", TargetID: access.Organization.ID.String(),
			Metadata: map[string]any{"slug": access.Organization.Slug, "name": access.Organization.Name},
		})
	})
}

// RestoreOrganization undeletes an organization, under a new slug if its old one
// has been taken since.
func (s *Service) RestoreOrganization(ctx context.Context, actor User, organizationID uuid.UUID, slug string) (Organization, error) {
	var org Organization
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		target := slug
		if target == "" {
			var current string
			err := db.QueryRow(ctx, `SELECT slug FROM organizations WHERE id = $1 AND deleted_at IS NOT NULL`,
				organizationID).Scan(&current)
			if err != nil {
				return ErrNotFound
			}
			target = current
		}
		target, err := normalizeSlug(target)
		if err != nil {
			return err
		}
		if org, err = repo.RestoreOrganization(ctx, organizationID, target); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			OrganizationID: &org.ID, ActorUserID: &actor.ID, Action: audit.ActionOrganizationRestored,
			TargetType: "organization", TargetID: org.ID.String(), Metadata: map[string]any{"slug": target},
		})
	})
	return org, err
}

// ListAllOrganizations returns every organization. System surface only.
func (s *Service) ListAllOrganizations(ctx context.Context, before uuid.UUID, limit int) ([]Organization, error) {
	return s.repo.ListAllOrganizations(ctx, before, limit)
}

// PurgeDeletedOrganizations hard-deletes organizations soft-deleted longer than
// retain ago. The transaction sets app.audit_purge, because the cascade destroys
// their audit entries too and the append-only trigger refuses anything else.
func (s *Service) PurgeDeletedOrganizations(ctx context.Context, retain time.Duration) (int64, error) {
	if retain <= 0 {
		return 0, nil
	}
	var purged int64
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		if _, err := db.Exec(ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		var err error
		purged, err = NewRepository(db).PurgeDeletedOrganizations(ctx, retain)
		return err
	})
	return purged, err
}

// ---------------------------------------------------------------- users

// ListAllUsers returns every user. System surface only.
func (s *Service) ListAllUsers(ctx context.Context, before uuid.UUID, limit int) ([]User, error) {
	return s.repo.ListAllUsers(ctx, before, limit)
}

// SetUserActive is the application's own kill switch for a person, on top of
// døckio. Deactivating revokes every session in the same transaction, so it takes
// effect on their very next request.
func (s *Service) SetUserActive(ctx context.Context, actor User, targetUserID uuid.UUID, isActive bool) (User, error) {
	if actor.ID == targetUserID && !isActive {
		return User{}, invalid("you cannot deactivate your own account")
	}
	var user User
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		var err error
		if user, err = repo.SetUserActive(ctx, targetUserID, isActive); err != nil {
			return err
		}
		action, metadata := audit.ActionUserReactivated, map[string]any{"email": user.Email}
		if !isActive {
			revoked, err := repo.RevokeUserSessions(ctx, targetUserID)
			if err != nil {
				return err
			}
			action, metadata["sessions_revoked"] = audit.ActionUserDeactivated, revoked
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: action, TargetType: "user", TargetID: targetUserID.String(), Metadata: metadata,
		})
	})
	return user, err
}

// ---------------------------------------------------------------- validation

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// reservedSlugs name routes, or ones you will want later. Reserving them costs
// nothing now and is impossible once somebody owns them.
var reservedSlugs = map[string]bool{
	"api": true, "auth": true, "admin": true, "app": true, "www": true, "static": true, "assets": true,
	"health": true, "healthz": true, "readyz": true, "metrics": true, "login": true, "logout": true,
	"signin": true, "signup": true, "me": true, "settings": true, "system": true, "support": true,
	"billing": true, "docs": true, "status": true, "new": true, "organizations": true, "b": true,
}

func normalizeSlug(slug string) (string, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	switch {
	case len(slug) < 2 || len(slug) > 63:
		return "", invalid("organization slug must be between 2 and 63 characters")
	case !slugPattern.MatchString(slug):
		return "", invalid("organization slug may contain only lowercase letters, digits, and single hyphens between them")
	case reservedSlugs[slug]:
		return "", invalid(fmt.Sprintf("organization slug %q is reserved", slug))
	}
	return slug, nil
}

var realmPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

func normalizeRealm(realm string) (*string, error) {
	realm = strings.TrimSpace(realm)
	if realm == "" {
		return nil, nil
	}
	if !realmPattern.MatchString(realm) {
		return nil, invalid("a døckio realm is lowercase letters, digits, '.', '_' and '-', at most 100 characters")
	}
	return &realm, nil
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	addr, err := netmail.ParseAddress(email)
	if email == "" || err != nil || addr.Address != email || len(email) > 254 {
		return "", invalid("email is not a valid address")
	}
	return email, nil
}

func (s *Service) validatePassword(password string) error {
	if len(password) < s.auth.MinPasswordLength {
		return invalid(fmt.Sprintf("password must be at least %d characters", s.auth.MinPasswordLength))
	}
	if len(password) > 1024 { // hashing a megabyte per attempt is a free denial of service
		return invalid("password must be at most 1024 characters")
	}
	return nil
}
