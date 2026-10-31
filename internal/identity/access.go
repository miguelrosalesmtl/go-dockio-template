package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
)

// What a caller may do is døckio's answer, not the application's. For a request
// inside an organization the application asks døckio for the person's effective
// permission keys in that organization's realm, maps them onto its own catalog,
// and caches the answer for DOCKIO_PERMISSION_CACHE_TTL (60 s by default).
//
// The cache is the whole trade-off, so be precise about it:
//
//   - A permission removed in døckio keeps working for at most one TTL. There is
//     no push; the next lookup after the TTL sees the change.
//   - When døckio cannot be reached, a cached answer is used until it is one TTL
//     old, and then the request is REFUSED (503). Business data fails closed.
//   - The cache is per process. N replicas ask døckio N times; none of them can
//     hold a stale answer longer than one TTL.

type effectiveEntry struct {
	eff     dockio.Effective
	fetched time.Time
}

type effectiveCache struct {
	mu      sync.Mutex
	entries map[string]effectiveEntry
}

func (c *effectiveCache) get(key string) (effectiveEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *effectiveCache) put(key string, e effectiveEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = e
}

// drop forgets every answer for one person in one realm ("" means all realms).
func (c *effectiveCache) drop(issuer, uid, realm string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if realm != "" {
		delete(c.entries, issuer+"|"+uid+"|"+realm)
		return
	}
	for k := range c.entries {
		if strings.HasPrefix(k, issuer+"|"+uid+"|") {
			delete(c.entries, k)
		}
	}
}

func (c *effectiveCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]effectiveEntry{}
}

// effectiveIn returns døckio's answer for ident in realm, from the cache when it
// is fresh enough.
func (s *Service) effectiveIn(ctx context.Context, ident OIDCIdentity, realm string) (dockio.Effective, error) {
	key := ident.Issuer + "|" + ident.UID + "|" + realm
	if e, ok := s.effective.get(key); ok && s.now().Sub(e.fetched) < s.dk.PermissionCacheTTL {
		return e.eff, nil
	}

	client, _, err := s.client(ctx)
	if err != nil {
		return dockio.Effective{}, err
	}
	eff, err := client.EffectiveIn(ctx, ident.Username, realm)
	switch {
	case errors.Is(err, dockio.ErrNoSuchPerson):
		return dockio.Effective{}, ErrNotFound
	case err != nil:
		// Expired secret, revoked client, station down: none of these is a
		// verdict about the person, and none of them may let them in either.
		s.log.Warn("døckio permission lookup failed -- refusing", slog.String("realm", realm), slog.String("error", err.Error()))
		return dockio.Effective{}, ErrDockioUnavailable
	}

	// The answer must be about the person we asked about. A username can be
	// re-used by somebody else after a rename; the uid cannot.
	if eff.ID != ident.UID {
		s.log.Error("døckio answered about another account -- refusing",
			slog.String("asked_uid", ident.UID), slog.String("answered_uid", eff.ID))
		return dockio.Effective{}, ErrNotFound
	}
	s.effective.put(key, effectiveEntry{eff: eff, fetched: s.now()})
	return eff, nil
}

// ResolveOrganization decides whether user may act in the organization named by
// slug, and with which permissions. It is the single choke point for organization
// authorization: every organization-scoped route passes through it.
//
// "Does not exist" and "you may not see it" are both ErrNotFound.
func (s *Service) ResolveOrganization(ctx context.Context, user User, session Session, slug string) (OrganizationAccess, error) {
	org, err := s.repo.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		return OrganizationAccess{}, err
	}

	// The local superuser: every permission, in every organization, audited by
	// the caller on every request.
	if user.IsSuperuser {
		return OrganizationAccess{Organization: org, Permissions: AllPermissions(), ViaSuperuser: true}, nil
	}
	if session.AuthMethod != AuthMethodDockio {
		return OrganizationAccess{}, ErrNotFound
	}

	ident, err := s.identityFor(ctx, user)
	if err != nil {
		return OrganizationAccess{}, err
	}

	// A døckio account holding system.superuser gets the same bypass, from the
	// home realm.
	if sys, err := s.systemPermissions(ctx, ident); err == nil && sys.Has(PermSystemSuperuser) {
		return OrganizationAccess{Organization: org, Permissions: AllPermissions(), ViaSuperuser: true}, nil
	} else if errors.Is(err, ErrDockioUnavailable) {
		return OrganizationAccess{}, err
	}

	realm := org.realm()
	if realm == "" {
		return OrganizationAccess{}, ErrNotFound // nowhere to look its people up
	}
	eff, err := s.effectiveIn(ctx, ident, realm)
	if err != nil {
		return OrganizationAccess{}, err
	}
	if eff.Disabled || !inRealm(eff, session, realm) {
		return OrganizationAccess{}, ErrNotFound
	}
	return OrganizationAccess{
		Organization: org,
		Permissions:  fromWireKeys(s.dk.AppKey, eff.Keys, Catalog),
	}, nil
}

// inRealm reports whether døckio says the person belongs to realm. When the
// answer lists realms, that list decides; otherwise the realms the id token
// listed at sign-in do (see the ASSUMPTIONS in docs/dockio.md).
func inRealm(eff dockio.Effective, session Session, realm string) bool {
	if eff.Realms != nil {
		return slices.Contains(eff.Realms, realm)
	}
	return slices.Contains(session.DockioRealms, realm)
}

// SystemAccess returns the caller's system permissions: everything for a local
// superuser; for a døckio account, what døckio grants them in the home realm.
func (s *Service) SystemAccess(ctx context.Context, user User, session Session) (PermissionSet, error) {
	if user.IsSuperuser {
		return AllSystemPermissions(), nil
	}
	if session.AuthMethod != AuthMethodDockio {
		return PermissionSet{}, nil
	}
	ident, err := s.identityFor(ctx, user)
	if err != nil {
		if isNotFound(err) {
			return PermissionSet{}, nil
		}
		return nil, err
	}
	return s.systemPermissions(ctx, ident)
}

func (s *Service) systemPermissions(ctx context.Context, ident OIDCIdentity) (PermissionSet, error) {
	eff, err := s.effectiveIn(ctx, ident, s.homeRealm(ctx))
	if isNotFound(err) {
		return PermissionSet{}, nil
	}
	if err != nil {
		return nil, err
	}
	if eff.Disabled {
		return PermissionSet{}, nil
	}
	return fromWireKeys(s.dk.AppKey, eff.Keys, SystemCatalog), nil
}

// homeRealm is the realm døckio put the application's own client in -- which may
// differ from DOCKIO_HOME_REALM if another tenant already held that slug.
func (s *Service) homeRealm(ctx context.Context) string {
	if c, err := s.repo.GetConnection(ctx); err == nil && c.HomeRealm != nil {
		return *c.HomeRealm
	}
	return s.dk.HomeRealm
}

// identityFor returns user's link under the CURRENT connection's issuer. A
// person linked under another tenant -- before a reconnect to a different one --
// has no identity here and so no access.
func (s *Service) identityFor(ctx context.Context, user User) (OIDCIdentity, error) {
	conn, err := s.repo.GetConnection(ctx)
	if errors.Is(err, ErrNotConnected) {
		return OIDCIdentity{}, ErrNotFound
	}
	if err != nil {
		return OIDCIdentity{}, err
	}
	return s.repo.GetIdentityForUser(ctx, user.ID, conn.Issuer)
}

// RecordSuperuserAccess writes the audit entry for a superuser entering an
// organization through the bypass. The middleware calls it on every such request
// and refuses the request if it fails: the bypass is acceptable only because it
// cannot happen unseen.
func (s *Service) RecordSuperuserAccess(ctx context.Context, user User, org Organization, method, path string) error {
	return audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		OrganizationID: &org.ID, ActorUserID: &user.ID, Action: audit.ActionSuperuserOrganizationAccessed,
		TargetType: "organization", TargetID: org.ID.String(),
		Metadata: map[string]any{"method": method, "path": path, "email": user.Email, "local": user.IsSuperuser},
	})
}

// client returns the døckio client for the stored connection, building it again
// only when the connection has changed since the last call.
func (s *Service) client(ctx context.Context) (*dockio.Client, ConnectionSettings, error) {
	conn, err := s.repo.GetConnection(ctx)
	if err != nil {
		return nil, ConnectionSettings{}, err
	}
	key := conn.Issuer + "|" + conn.ClientID + "|" + conn.UpdatedAt.String()

	s.rpMu.Lock()
	defer s.rpMu.Unlock()
	if s.rp != nil && s.rpKey == key {
		return s.rp, conn, nil
	}
	secret, err := s.box.OpenString(conn.ClientSecretEnc)
	if err != nil {
		return nil, conn, fmt.Errorf("identity: the stored client secret cannot be unsealed -- was SECRETS_KEY changed? %w", err)
	}
	c, err := dockio.NewClient(ctx, dockio.Config{
		Issuer: conn.Issuer, ClientID: conn.ClientID, ClientSecret: secret, HTTP: s.http,
	})
	if err != nil {
		if errors.Is(err, dockio.ErrUnavailable) {
			return nil, conn, ErrDockioUnavailable
		}
		return nil, conn, err
	}
	s.rp, s.rpKey = c, key
	return c, conn, nil
}

// forgetClient drops the cached client and every cached answer. Called whenever
// the connection changes.
func (s *Service) forgetClient() {
	s.rpMu.Lock()
	s.rp, s.rpKey = nil, ""
	s.rpMu.Unlock()
	s.effective.clear()
}
