package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
)

// The døckio connection: one OIDC client for the whole installation, made with
// app connect (SOIDC v1 §14, "Quick connect") or typed in by hand.
//
//	start     POST /api/v1/system/signin/connect   -> {redirect_url}; browser to døckio
//	callback  GET  /api/v1/auth/oidc/connect/callback?code&state
//	          exchange the code, validate the grant, save, sync the catalog
//	revoke    POST /api/v1/dockio/connection-revoked  (døckio's signed notice)
//	renew     the same round trip, with connection=<id>
//	disconnect DELETE /api/v1/system/signin/connection
//
// docs/dockio.md has the narrative and the security checklist every step below
// answers to.

// Connection paths on this API. They go into the manifest, so døckio registers
// them; changing one means reconnecting.
const (
	PathManifest           = "/api/v1/dockio/manifest"
	PathConnectionRevoked  = "/api/v1/dockio/connection-revoked"
	PathConnectCallback    = "/api/v1/auth/oidc/connect/callback"
	PathSigninCallback     = "/api/v1/auth/oidc/callback"
	PathBackchannelLogout  = "/api/v1/auth/oidc/backchannel-logout"
	PathSignedOut          = "/api/v1/auth/signed-out"
	attemptTTL             = 10 * time.Minute
	expiringWithin         = 30 * 24 * time.Hour
	connectionStatusNone   = "none"
	connectionStatusManual = "manual"
)

// Connection statuses. Computed, never stored.
const (
	StatusNone     = connectionStatusNone   // no connection
	StatusManual   = connectionStatusManual // set up by hand; never expires
	StatusActive   = "active"               // more than 30 days left
	StatusExpiring = "expiring"             // 30 days or fewer left
	StatusExpired  = "expired"              // past secret_expires_at
	StatusRevoked  = "revoked"              // døckio's notice arrived
)

// Status computes the connection's status. Revoked is checked before expired.
func (c ConnectionSettings) Status(now time.Time) string {
	switch {
	case c.ConnectionID == nil:
		return StatusManual
	case c.RevokedAt != nil:
		return StatusRevoked
	case c.SecretExpiresAt != nil && !now.Before(*c.SecretExpiresAt):
		return StatusExpired
	case c.SecretExpiresAt != nil && c.SecretExpiresAt.Sub(now) <= expiringWithin:
		return StatusExpiring
	default:
		return StatusActive
	}
}

// usable reports whether people can sign in through this connection at all.
func usable(status string) bool {
	return status == StatusActive || status == StatusExpiring || status == StatusManual
}

// ConnectionView is the connection as the settings page shows it. It never
// carries the secret.
type ConnectionView struct {
	Status        string     `json:"status"`
	Enabled       bool       `json:"enabled"`
	Issuer        string     `json:"issuer,omitempty"`
	ClientID      string     `json:"client_id,omitempty"`
	ConnectionID  string     `json:"connection_id,omitempty"`
	TenantName    string     `json:"tenant_name,omitempty"`
	TenantAddress string     `json:"tenant_address,omitempty"`
	Realm         string     `json:"realm,omitempty"`
	ManageURI     string     `json:"manage_uri,omitempty"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	ConnectedBy   *uuid.UUID `json:"connected_by,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	DaysLeft      *int       `json:"days_left,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`

	CatalogVersion  *int64     `json:"catalog_version,omitempty"`
	CatalogSyncedAt *time.Time `json:"catalog_synced_at,omitempty"`
	CatalogCurrent  uint64     `json:"catalog_current"`

	// Defaults for the Quick connect form's two addresses.
	DefaultStationURL string `json:"default_station_url"`
	PublicURL         string `json:"public_url"`
}

// Connection returns the connection for the settings page.
func (s *Service) Connection(ctx context.Context) (ConnectionView, error) {
	v := ConnectionView{
		Status: StatusNone, CatalogCurrent: CatalogVersion,
		DefaultStationURL: s.dk.StationURL, PublicURL: s.dk.PublicURL,
	}
	c, err := s.repo.GetConnection(ctx)
	if errors.Is(err, ErrNotConnected) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	now := s.now()
	v.Status, v.Enabled, v.Issuer, v.ClientID = c.Status(now), c.Enabled, c.Issuer, c.ClientID
	v.ConnectionID, v.TenantName, v.TenantAddress = deref(c.ConnectionID), deref(c.TenantName), deref(c.TenantAddress)
	v.Realm, v.ManageURI = deref(c.HomeRealm), deref(c.ManageURI)
	v.ConnectedAt, v.ConnectedBy, v.ExpiresAt, v.RevokedAt = c.ConnectedAt, c.ConnectedBy, c.SecretExpiresAt, c.RevokedAt
	v.CatalogVersion, v.CatalogSyncedAt = c.CatalogVersion, c.CatalogSyncedAt
	if c.SecretExpiresAt != nil {
		days := int(c.SecretExpiresAt.Sub(now).Hours() / 24)
		v.DaysLeft = &days
	}
	return v, nil
}

// SigninAvailable reports whether "Continue with døckio" can work right now. The
// login page reads it, so it can say "an administrator must renew the døckio
// connection" instead of showing a button that fails.
func (s *Service) SigninAvailable(ctx context.Context) (bool, error) {
	c, err := s.repo.GetConnection(ctx)
	if errors.Is(err, ErrNotConnected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return c.Enabled && usable(c.Status(s.now())), nil
}

// Manifest is what døckio fetches while an operator approves a connection.
func (s *Service) Manifest() dockio.Manifest {
	base := strings.TrimRight(s.dk.PublicURL, "/")
	return dockio.Manifest{
		Version:                "1",
		Name:                   s.dk.AppName,
		LogoURI:                s.dk.LogoURI,
		AppKey:                 s.dk.AppKey,
		RedirectURIs:           []string{base + PathSigninCallback},
		PostLogoutRedirectURIs: []string{base + PathSignedOut},
		BackchannelLogoutURI:   base + PathBackchannelLogout,
		RevocationURI:          base + PathConnectionRevoked,
		Needs:                  s.dk.Needs,
		HomeRealm:              s.dk.HomeRealm,
		MaxExpiryDays:          s.dk.MaxExpiryDays,
	}
}

// ---------------------------------------------------------------- start

// StartConnect begins Quick connect for actor and returns where to send the
// browser, plus the state the server must put in a short-lived cookie.
//
// A first connect goes to stationURL (or DOCKIO_STATION_URL). A renewal goes to
// the station of the stored issuer and names the stored connection, so døckio
// rotates the secret instead of making a new client.
func (s *Service) StartConnect(ctx context.Context, actor User, stationURL string, renew bool) (redirectURL, state string, err error) {
	var connectionID *string
	if renew {
		c, err := s.repo.GetConnection(ctx)
		if err != nil {
			return "", "", err
		}
		if c.ConnectionID == nil {
			return "", "", invalid("a connection set up by hand cannot be renewed -- use Quick connect")
		}
		connectionID = c.ConnectionID
		// The station is the origin of the stored issuer; the issuer itself is a
		// tenant path on it.
		if stationURL, err = dockio.Origin(c.Issuer); err != nil {
			return "", "", err
		}
	} else if strings.TrimSpace(stationURL) == "" {
		stationURL = s.dk.StationURL
	}
	stationURL = strings.TrimRight(strings.TrimSpace(stationURL), "/")

	// Discovery validates that every endpoint is on the station's origin: the
	// browser goes to one of them, and the code (soon the secret) to another.
	disc, err := dockio.FetchDiscovery(ctx, s.http, stationURL)
	switch {
	case errors.Is(err, dockio.ErrBadURL):
		return "", "", invalid(err.Error())
	case err != nil:
		return "", "", ErrDockioUnavailable
	case !disc.SupportsConnect():
		return "", "", ErrConnectNotSupported
	}

	state, err = dockio.RandomToken(32)
	if err != nil {
		return "", "", err
	}
	pkce, err := dockio.NewPKCE()
	if err != nil {
		return "", "", err
	}
	verifierEnc, err := s.box.SealString(pkce.Verifier)
	if err != nil {
		return "", "", err
	}
	if err := s.repo.CreateConnectAttempt(ctx, hashState(state), ConnectAttempt{
		CodeVerifierEnc: verifierEnc, UserID: actor.ID, StationURL: stationURL,
		PublicURL: s.dk.PublicURL, Renew: renew, ConnectionID: connectionID,
	}, attemptTTL); err != nil {
		return "", "", err
	}

	base := strings.TrimRight(s.dk.PublicURL, "/")
	req := dockio.ConnectRequest{
		ManifestURI: base + PathManifest, ReturnURI: base + PathConnectCallback,
		State: state, CodeChallenge: pkce.Challenge,
	}
	if connectionID != nil {
		req.ConnectionID = *connectionID
	}
	return dockio.ConnectURL(disc, req), state, nil
}

// ---------------------------------------------------------------- callback

// ConnectResult is what CompleteConnect reports to the settings page.
type ConnectResult string

// Connect results.
const (
	ConnectConnected ConnectResult = "connected"
	ConnectRenewed   ConnectResult = "renewed"
)

// CompleteConnect finishes Quick connect. It is called from a PUBLIC route: the
// session cookie is usually SameSite=Strict and does not survive døckio's
// cross-site redirect. So the callback is bound twice instead:
//
//   - to the BROWSER that started it: cookieState must equal state (compared in
//     constant time by the caller's helper, sameState);
//   - to the PERSON: the attempt row names them, and their permission to change
//     sign-in is checked AGAIN here, before anything is saved.
//
// Every failure is a *FlowError whose Code goes into the redirect.
func (s *Service) CompleteConnect(ctx context.Context, cookieState, state, code, errParam string) (ConnectResult, error) {
	if !sameState(cookieState, state) {
		return "", flowError(CodeInvalidState, errors.New("connect state cookie missing or mismatched"))
	}
	attempt, err := s.repo.TakeConnectAttempt(ctx, hashState(state))
	if isNotFound(err) {
		return "", flowError(CodeInvalidState, errors.New("no live connect attempt for that state"))
	}
	if err != nil {
		return "", err
	}
	if errParam != "" {
		return "", flowError(CodeConnectCancelled, fmt.Errorf("døckio answered %q", errParam))
	}

	actor, err := s.repo.GetUserByID(ctx, attempt.UserID)
	if err != nil || !actor.IsActive {
		return "", flowError(CodeConnectForbidden, errors.New("the person who started the connect is gone or deactivated"))
	}
	if ok, err := s.maySetSignin(ctx, actor); err != nil || !ok {
		return "", flowError(CodeConnectForbidden, err)
	}

	verifier, err := s.box.OpenString(attempt.CodeVerifierEnc)
	if err != nil {
		return "", err
	}
	disc, err := dockio.FetchDiscovery(ctx, s.http, attempt.StationURL)
	if err != nil {
		return "", flowError(CodeDockioUnavailable, err)
	}
	returnURI := strings.TrimRight(attempt.PublicURL, "/") + PathConnectCallback
	grant, err := dockio.ExchangeConnectCode(ctx, s.http, disc, code, verifier, returnURI)
	switch {
	case errors.Is(err, dockio.ErrInvalidGrant):
		return "", flowError(CodeConnectExpired, err)
	case err != nil:
		return "", flowError(CodeDockioUnavailable, err)
	}

	previous, prevErr := s.repo.GetConnection(ctx)
	hadPrevious := prevErr == nil
	if prevErr != nil && !errors.Is(prevErr, ErrNotConnected) {
		return "", prevErr
	}
	if err := s.validateGrant(grant, attempt, previous, hadPrevious); err != nil {
		return "", flowError(CodeConnectInvalidGrant, err)
	}

	// Build a client from the grant before saving anything: it proves the tenant
	// issuer's discovery is sound and is what disconnects, syncs and retires below.
	fresh, err := dockio.NewClient(ctx, dockio.Config{
		Issuer: grant.Issuer, ClientID: grant.ClientID, ClientSecret: grant.ClientSecret, HTTP: s.http,
	})
	if err != nil {
		return "", flowError(CodeDockioUnavailable, err)
	}

	// Refuse a tenant switch while organizations are linked to realms in the old
	// tenant -- their people would be stranded -- and disconnect what we were just
	// given, so it does not linger as a live credential nobody holds.
	if hadPrevious && !dockio.SameIssuer(previous.Issuer, grant.Issuer) {
		n, err := s.repo.CountOrganizationsWithRealm(ctx)
		if err != nil {
			return "", err
		}
		if n > 0 {
			if _, derr := fresh.Disconnect(ctx); derr != nil {
				s.log.Error("could not disconnect a refused connection -- remove it in døckio's console",
					slog.String("connection_id", grant.ConnectionID), slog.String("error", derr.Error()))
			}
			return "", flowError(CodeConnectOtherTenant,
				fmt.Errorf("%d organizations are linked to realms in %s", n, previous.Issuer))
		}
	}

	secretEnc, err := s.box.SealString(grant.ClientSecret)
	if err != nil {
		return "", err
	}
	now := s.now().Truncate(time.Second) // the revocation replay rule compares with a 1 s iat
	saved := ConnectionSettings{
		Issuer: grant.Issuer, ClientID: grant.ClientID, ClientSecretEnc: secretEnc,
		// A first connect leaves sign-in OFF until an admin has looked at it. A
		// renewal keeps it as it was.
		Enabled:      hadPrevious && attempt.Renew && previous.Enabled,
		ConnectionID: &grant.ConnectionID, TenantName: &grant.Tenant.Name, TenantAddress: &grant.Tenant.Address,
		HomeRealm: &grant.Realm, ManageURI: nullIfEmpty(grant.ManageURI),
		ConnectedAt: &now, ConnectedBy: &actor.ID,
	}
	if grant.ClientSecretExpiresAt != nil {
		exp := time.Unix(*grant.ClientSecretExpiresAt, 0)
		saved.SecretExpiresAt = &exp
	}
	result, action := ConnectConnected, audit.ActionConnectionConnected
	if attempt.Renew {
		result, action = ConnectRenewed, audit.ActionConnectionRenewed
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		if _, err := repo.LockConnection(ctx); err != nil && !errors.Is(err, ErrNotConnected) {
			return err
		}
		if err := repo.SaveConnection(ctx, saved); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: action, TargetType: "connection", TargetID: grant.ConnectionID,
			Metadata: map[string]any{
				"issuer": grant.Issuer, "client_id": grant.ClientID, "tenant": grant.Tenant.Address,
				"realm": grant.Realm, "expires_at": saved.SecretExpiresAt,
			},
		})
	})
	if err != nil {
		return "", err
	}
	s.forgetClient()

	// The catalog is synced even though sign-in is still off: døckio's role
	// editor needs the keys before anybody can be granted anything.
	if err := s.SyncCatalog(ctx); err != nil {
		s.log.Warn("connected, but the permission catalog could not be published -- retry from the sign-in page",
			slog.String("error", err.Error()))
	}

	// A connect that replaced a DIFFERENT connection retires the old one at
	// døckio, so no live credential is left behind.
	if hadPrevious && previous.ConnectionID != nil && *previous.ConnectionID != grant.ConnectionID {
		s.retire(ctx, previous)
	}
	return result, nil
}

// validateGrant checks døckio's answer before anything is trusted.
func (s *Service) validateGrant(g dockio.Grant, attempt ConnectAttempt, previous ConnectionSettings, hadPrevious bool) error {
	switch {
	case g.Issuer == "" || g.ClientID == "" || g.ClientSecret == "" || g.ConnectionID == "":
		return errors.New("the grant lacks an issuer, client id, secret or connection id")
	case !dockio.SameOrigin(g.Issuer, attempt.StationURL):
		return fmt.Errorf("the grant's issuer %q is not on the station %q", g.Issuer, attempt.StationURL)
	case dockio.CheckSecure(g.Issuer) != nil:
		return fmt.Errorf("the grant's issuer %q is not https", g.Issuer)
	case g.AppKey != nil && *g.AppKey != s.dk.AppKey:
		return fmt.Errorf("the grant is for app_key %q, not %q", *g.AppKey, s.dk.AppKey)
	case g.ManageURI != "" && !dockio.SameOrigin(g.ManageURI, attempt.StationURL):
		return fmt.Errorf("the grant's manage_uri %q is not on the station", g.ManageURI)
	}
	if attempt.Renew {
		switch {
		case attempt.ConnectionID == nil || g.ConnectionID != *attempt.ConnectionID:
			return errors.New("a renewal came back with another connection")
		case !hadPrevious || !dockio.SameIssuer(previous.Issuer, g.Issuer):
			return errors.New("a renewal came back under another tenant")
		}
	}
	return nil
}

// retire disconnects a replaced connection, best effort.
func (s *Service) retire(ctx context.Context, old ConnectionSettings) {
	secret, err := s.box.OpenString(old.ClientSecretEnc)
	if err == nil {
		var c *dockio.Client
		c, err = dockio.NewClient(ctx, dockio.Config{Issuer: old.Issuer, ClientID: old.ClientID, ClientSecret: secret, HTTP: s.http})
		if err == nil {
			_, err = c.Disconnect(ctx)
		}
	}
	if err != nil {
		s.log.Warn("could not retire the replaced døckio connection -- revoke it in døckio's console",
			slog.String("connection_id", deref(old.ConnectionID)), slog.String("error", err.Error()))
	}
}

// maySetSignin re-checks, at the callback, that actor may still change sign-in.
func (s *Service) maySetSignin(ctx context.Context, actor User) (bool, error) {
	if actor.IsSuperuser {
		return true, nil
	}
	ident, err := s.identityFor(ctx, actor)
	if err != nil {
		return false, err
	}
	perms, err := s.systemPermissions(ctx, ident)
	if err != nil {
		return false, err
	}
	return perms.Has(PermSystemSignin), nil
}

// ---------------------------------------------------------------- disconnect

// Disconnect revokes the connection at døckio and forgets it here.
//
// It ALWAYS clears locally, even when døckio cannot be reached: disconnecting
// must always work. The result says whether døckio was told, so the page can ask
// the admin to finish the job in døckio's console when it was not.
func (s *Service) Disconnect(ctx context.Context, actor User) (dockioTold bool, err error) {
	c, err := s.repo.GetConnection(ctx)
	if err != nil {
		return false, err
	}
	if c.ConnectionID != nil {
		if client, _, cerr := s.client(ctx); cerr == nil {
			if _, derr := client.Disconnect(ctx); derr == nil {
				dockioTold = true
			} else {
				s.log.Warn("disconnecting locally, but døckio could not be told", slog.String("error", derr.Error()))
			}
		}
	}
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).DeleteConnection(ctx); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: audit.ActionConnectionDisconnected, TargetType: "connection",
			TargetID: deref(c.ConnectionID),
			Metadata: map[string]any{"issuer": c.Issuer, "client_id": c.ClientID, "dockio_told": dockioTold},
		})
	})
	s.forgetClient()
	return dockioTold, err
}

// ---------------------------------------------------------------- manual setup

// SaveManualConnection stores a client typed in by hand: the fallback for a
// station without app connect. It never expires and cannot be renewed or revoked
// from here. Sign-in starts OFF, as with Quick connect.
func (s *Service) SaveManualConnection(ctx context.Context, actor User, issuer, clientID, clientSecret string) error {
	issuer, clientID = strings.TrimRight(strings.TrimSpace(issuer), "/"), strings.TrimSpace(clientID)
	if issuer == "" || clientID == "" || clientSecret == "" {
		return invalid("issuer, client id and client secret are all required")
	}
	if err := dockio.CheckSecure(issuer); err != nil {
		return invalid(err.Error())
	}
	// Discovery proves the issuer is a real døckio before we store anything.
	if _, err := dockio.NewClient(ctx, dockio.Config{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, HTTP: s.http}); err != nil {
		if errors.Is(err, dockio.ErrUnavailable) {
			return ErrDockioUnavailable
		}
		return invalid(err.Error())
	}
	secretEnc, err := s.box.SealString(clientSecret)
	if err != nil {
		return err
	}
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		if _, err := repo.LockConnection(ctx); err != nil && !errors.Is(err, ErrNotConnected) {
			return err
		}
		if err := repo.SaveConnection(ctx, ConnectionSettings{Issuer: issuer, ClientID: clientID, ClientSecretEnc: secretEnc}); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: audit.ActionConnectionManualSaved, TargetType: "connection",
			Metadata: map[string]any{"issuer": issuer, "client_id": clientID},
		})
	})
	if err != nil {
		return err
	}
	s.forgetClient()
	if err := s.SyncCatalog(ctx); err != nil {
		s.log.Warn("saved, but the permission catalog could not be published", slog.String("error", err.Error()))
	}
	return nil
}

// SetSigninEnabled turns sign-in with døckio on or off. It cannot be turned on
// over a connection nobody can sign in through.
func (s *Service) SetSigninEnabled(ctx context.Context, actor User, enabled bool) error {
	c, err := s.repo.GetConnection(ctx)
	if err != nil {
		return err
	}
	if enabled && !usable(c.Status(s.now())) {
		return invalid("the connection is " + c.Status(s.now()) + " -- renew or reconnect it first")
	}
	action := audit.ActionSigninDisabled
	if enabled {
		action = audit.ActionSigninEnabled
	}
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).SetSigninEnabled(ctx, enabled); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID, Action: action, TargetType: "connection", TargetID: deref(c.ConnectionID),
		})
	})
}

// ---------------------------------------------------------------- revocation

// ConnectionRevoked handles døckio's signed revocation notice.
//
// An unknown or invalid notice changes nothing (ErrInvalidNotice -> 400). A
// repeat for a connection already revoked succeeds (-> 204): døckio retries until
// it gets a 2xx, and a 400 would keep it trying.
func (s *Service) ConnectionRevoked(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return ErrInvalidNotice
	}
	client, conn, err := s.client(ctx)
	if errors.Is(err, ErrNotConnected) {
		return ErrInvalidNotice
	}
	if err != nil {
		return err
	}
	rev, err := client.VerifyRevocation(ctx, rawToken)
	if errors.Is(err, dockio.ErrUnavailable) {
		return ErrDockioUnavailable // a 503: døckio will retry
	}
	if err != nil || conn.ConnectionID == nil || rev.ConnectionID != *conn.ConnectionID {
		s.rejectNotice(ctx, err)
		return ErrInvalidNotice
	}
	if conn.RevokedAt != nil {
		return nil // a repeat
	}
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		changed, err := NewRepository(db).MarkRevoked(ctx, rev.ConnectionID, rev.IssuedAt)
		if err != nil {
			return err
		}
		if !changed {
			// Issued before the current connection was made: a replay of a notice
			// about an earlier incarnation.
			return ErrInvalidNotice
		}
		s.forgetClient()
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			Action: audit.ActionConnectionRevoked, TargetType: "connection", TargetID: rev.ConnectionID,
			Metadata: map[string]any{"reason": rev.Reason, "jti": rev.JTI},
		})
	})
}

func (s *Service) rejectNotice(ctx context.Context, cause error) {
	detail := "connection_id mismatch"
	if cause != nil {
		detail = cause.Error()
	}
	if err := audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		Action: audit.ActionNoticeRejected, TargetType: "connection", Metadata: map[string]any{"detail": detail},
	}); err != nil {
		s.log.Error("could not audit a rejected revocation notice", slog.String("error", err.Error()))
	}
}

// ---------------------------------------------------------------- catalog

// SyncCatalog publishes the permission catalog to døckio and records the version.
func (s *Service) SyncCatalog(ctx context.Context) error {
	client, _, err := s.client(ctx)
	if err != nil {
		return err
	}
	cat := DockioCatalog(s.dk.AppKey)
	if _, err := client.SyncCatalog(ctx, cat); err != nil {
		if errors.Is(err, dockio.ErrCatalogVersionConflict) {
			s.log.Warn("døckio holds a newer permission catalog than this build -- a rolled-back deploy? Keys this build lacks stay deprecated, not deleted.",
				slog.Uint64("this_build", cat.Version))
			return nil
		}
		return err
	}
	return s.repo.SetCatalogSynced(ctx, cat.Version)
}

// ---------------------------------------------------------------- helpers

func hashState(state string) []byte {
	sum := sha256.Sum256([]byte(state))
	return sum[:]
}
