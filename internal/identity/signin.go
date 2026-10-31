package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
)

// Sign-in through døckio: OpenID Connect authorization code flow with PKCE, run
// entirely on the server. The application is a backend-for-frontend: the browser
// carries only a session cookie, never a døckio token.
//
//	start     GET /api/v1/auth/oidc/login[?organization=<slug>&return_to=/path]
//	callback  GET /api/v1/auth/oidc/callback?code&state
//	sign out  POST /api/v1/auth/logout -> {logout_url}: ends the døckio session too
//	døckio    POST /api/v1/auth/oidc/backchannel-logout (a signed logout token)

// StartSignIn begins a sign-in and returns where to send the browser, plus the
// state the server must put in a short-lived cookie.
//
// With orgSlug, the attempt is for that organization's realm: døckio shows the
// realm's branding, and the person must come back signed in to THAT realm.
func (s *Service) StartSignIn(ctx context.Context, orgSlug, returnTo string) (redirectURL, state string, err error) {
	client, conn, err := s.client(ctx)
	if errors.Is(err, ErrNotConnected) {
		return "", "", flowError(CodeSigninUnavailable, err)
	}
	if err != nil {
		return "", "", flowError(CodeDockioUnavailable, err)
	}
	if !conn.Enabled || !usable(conn.Status(s.now())) {
		return "", "", flowError(CodeSigninUnavailable, errors.New("sign-in is off, or the connection is "+conn.Status(s.now())))
	}

	var realm *string
	if orgSlug != "" {
		org, err := s.repo.GetOrganizationBySlug(ctx, orgSlug)
		if err != nil {
			return "", "", err
		}
		if org.DockioRealm == nil {
			return "", "", ErrNotFound
		}
		realm = org.DockioRealm
	}

	state, err = dockio.RandomToken(32)
	if err != nil {
		return "", "", err
	}
	nonce, err := dockio.RandomToken(32)
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
	if err := s.repo.CreateLoginAttempt(ctx, hashState(state), LoginAttempt{
		Nonce: nonce, CodeVerifierEnc: verifierEnc, Realm: realm, ReturnTo: safeReturnTo(returnTo),
	}, attemptTTL); err != nil {
		return "", "", err
	}

	req := dockio.AuthRequest{
		RedirectURI: s.redirectURI(), State: state, Nonce: nonce, Challenge: pkce.Challenge,
	}
	if realm != nil {
		req.Realm = *realm
	}
	return client.AuthCodeURL(req), state, nil
}

// SignInResult is a completed sign-in.
type SignInResult struct {
	Token    string // the session token: the server puts it in the session cookie
	ReturnTo string // where the front end asked to land, a path on APP_BASE_URL
	User     User
}

// CompleteSignIn finishes a sign-in. Like the connect callback, it is a public
// route bound to the browser by the state cookie. Every failure is a *FlowError
// whose Code goes into the redirect to the login page.
func (s *Service) CompleteSignIn(ctx context.Context, cookieState, state, code, errParam string, meta RequestMeta) (SignInResult, error) {
	if !sameState(cookieState, state) {
		return SignInResult{}, flowError(CodeInvalidState, errors.New("sign-in state cookie missing or mismatched"))
	}
	attempt, err := s.repo.TakeLoginAttempt(ctx, hashState(state))
	if isNotFound(err) {
		return SignInResult{}, flowError(CodeInvalidState, errors.New("no live sign-in attempt for that state"))
	}
	if err != nil {
		return SignInResult{}, err
	}
	if errParam != "" {
		return SignInResult{}, flowError(CodeAccessDenied, fmt.Errorf("døckio answered %q", errParam))
	}

	// The connection is checked again: it may have been revoked, or sign-in
	// turned off, while the person was at døckio.
	client, conn, err := s.client(ctx)
	if err != nil {
		return SignInResult{}, flowError(CodeSigninUnavailable, err)
	}
	if !conn.Enabled || !usable(conn.Status(s.now())) {
		return SignInResult{}, flowError(CodeSigninUnavailable, errors.New("the connection is "+conn.Status(s.now())))
	}

	verifier, err := s.box.OpenString(attempt.CodeVerifierEnc)
	if err != nil {
		return SignInResult{}, err
	}
	tokens, err := client.Exchange(ctx, code, s.redirectURI(), verifier)
	switch {
	case errors.Is(err, dockio.ErrSecretExpired):
		return SignInResult{}, flowError(CodeConnectionExpired, err)
	case errors.Is(err, dockio.ErrUnavailable):
		return SignInResult{}, flowError(CodeDockioUnavailable, err)
	case err != nil:
		return SignInResult{}, flowError(CodeSigninExpired, err)
	case tokens.IDToken == "":
		return SignInResult{}, flowError(CodeInvalidToken, errors.New("no id_token in the token response"))
	}
	claims, err := client.VerifyIDToken(ctx, tokens.IDToken, attempt.Nonce)
	if errors.Is(err, dockio.ErrUnavailable) {
		return SignInResult{}, flowError(CodeDockioUnavailable, err)
	}
	if err != nil {
		s.recordFailedLogin(ctx, nil, map[string]any{"reason": "invalid_id_token", "detail": err.Error()})
		return SignInResult{}, flowError(CodeInvalidToken, err)
	}

	// Isolation at sign-in is the application's job: an attempt started for one
	// realm must come back signed in to exactly that realm.
	if attempt.Realm != nil && claims.Realm != *attempt.Realm {
		s.recordFailedLogin(ctx, nil, map[string]any{
			"reason": "wrong_realm", "uid": claims.UID, "asked": *attempt.Realm, "got": claims.Realm,
		})
		return SignInResult{}, flowError(CodeWrongRealm, fmt.Errorf("asked for realm %q, got %q", *attempt.Realm, claims.Realm))
	}

	idTokenEnc, err := s.box.SealString(tokens.IDToken)
	if err != nil {
		return SignInResult{}, err
	}

	var result SignInResult
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		user, err := s.linkAccount(ctx, repo, conn.Issuer, claims)
		if err != nil {
			return err
		}
		if !user.IsActive {
			return flowError(CodeAccountDeactivated, errors.New("the application deactivated this user"))
		}
		token, err := s.newSession(ctx, db, NewSession{
			UserID: user.ID, UserAgent: meta.UserAgent, IPAddress: meta.IPAddress, AuthMethod: AuthMethodDockio,
			DockioUID: claims.UID, DockioSID: claims.SID, DockioRealms: claims.Realms, IDTokenEnc: idTokenEnc,
		})
		if err != nil {
			return err
		}
		result = SignInResult{Token: token, ReturnTo: attempt.ReturnTo, User: user}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID, Action: audit.ActionUserSignedIn, TargetType: "user", TargetID: user.ID.String(),
			Metadata: map[string]any{
				"method": AuthMethodDockio, "uid": claims.UID, "username": claims.Username(),
				"realm": claims.Realm, "ip": meta.IPAddress, "user_agent": meta.UserAgent,
			},
		})
	})
	if err != nil {
		var fe *FlowError
		if errors.As(err, &fe) {
			s.recordFailedLogin(ctx, nil, map[string]any{"reason": fe.Code, "uid": claims.UID})
		}
		return SignInResult{}, err
	}
	// A fresh sign-in is a natural moment to re-ask døckio.
	s.effective.drop(conn.Issuer, claims.UID, "")
	return result, nil
}

// linkAccount finds the local user for a døckio account by (issuer, uid) --
// never by sub, username or email -- creating it the first time, and refreshes
// the copies of name and email.
func (s *Service) linkAccount(ctx context.Context, repo *Repository, issuer string, c dockio.IDClaims) (User, error) {
	first, last := c.GivenName, c.FamilyName
	if first == "" && last == "" {
		first = c.Name
	}
	ident, err := repo.GetIdentity(ctx, issuer, c.UID)
	switch {
	case err == nil:
		if err := repo.SetIdentityUsername(ctx, ident.ID, c.Username()); err != nil {
			return User{}, err
		}
		return repo.RefreshUser(ctx, ident.UserID, c.Email, first, last)
	case isNotFound(err):
		user, err := repo.CreateUser(ctx, c.Email, first, last)
		if err != nil {
			return User{}, err
		}
		if _, err := repo.CreateIdentity(ctx, user.ID, issuer, c.UID, c.Username()); err != nil {
			return User{}, err
		}
		return user, nil
	default:
		return User{}, err
	}
}

// SignOut ends the session behind token and returns where to send the browser to
// end the døckio session too ("" for a local superuser, or when døckio publishes
// no end-session endpoint). Sign-out always succeeds locally.
func (s *Service) SignOut(ctx context.Context, user User, session Session) (string, error) {
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSession(ctx, session.TokenHash); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID, Action: audit.ActionUserSignedOut, TargetType: "user", TargetID: user.ID.String(),
		})
	})
	if err != nil {
		return "", err
	}
	if session.AuthMethod != AuthMethodDockio {
		return "", nil
	}
	client, _, err := s.client(ctx)
	if err != nil {
		// Signed out here; døckio's own session simply outlives ours.
		s.log.Warn("signed out locally, but cannot point the browser at døckio", slog.String("error", err.Error()))
		return "", nil //nolint:nilerr // sign-out succeeded; only the døckio half is skipped
	}
	hint, _ := s.box.OpenString(session.IDTokenEnc)
	return client.EndSessionURL(hint, strings.TrimRight(s.dk.PublicURL, "/")+PathSignedOut), nil
}

// BackchannelLogout handles døckio's signed logout token.
//
// It ends one døckio session (sid) or every session of an account (uid). With a
// dockio_realm claim, the person stays signed in but loses that realm: only that
// organization's access and cached permissions are dropped.
//
// If acting on the token fails, its jti is released so døckio's retry is not
// refused as a replay.
func (s *Service) BackchannelLogout(ctx context.Context, rawToken string) error {
	client, conn, err := s.client(ctx)
	if err != nil {
		return ErrInvalidNotice
	}
	claims, err := client.VerifyLogoutToken(ctx, rawToken)
	if errors.Is(err, dockio.ErrUnavailable) {
		return ErrDockioUnavailable
	}
	if err != nil {
		s.log.Warn("refused a back-channel logout token", slog.String("error", err.Error()))
		return ErrInvalidNotice
	}

	uid := claims.UID
	if uid == "" && claims.SID == "" {
		// Only a subject: the username, which can change. Resolve it through the
		// stored link, which is kept current at every sign-in.
		var found string
		err := s.pool.QueryRow(ctx,
			`SELECT uid FROM oidc_identities WHERE issuer = $1 AND username = $2`, conn.Issuer, claims.Subject).Scan(&found)
		if err != nil {
			return nil //nolint:nilerr // nobody here by that name: nothing to end
		}
		uid = found
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)
		var n int64
		var err error
		if claims.Realm != "" && uid != "" {
			n, err = repo.DropRealmFromSessions(ctx, uid, claims.Realm)
		} else {
			n, err = repo.RevokeDockioSessions(ctx, uid, claims.SID)
		}
		if err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			Action: audit.ActionBackchannelLogout, TargetType: "dockio_account", TargetID: uid,
			Metadata: map[string]any{"sid": claims.SID, "realm": claims.Realm, "sessions": n},
		})
	})
	if err != nil {
		client.ReleaseJTI(rawToken)
		return err
	}
	if uid != "" {
		s.effective.drop(conn.Issuer, uid, claims.Realm)
	}
	return nil
}

func (s *Service) redirectURI() string {
	return strings.TrimRight(s.dk.PublicURL, "/") + PathSigninCallback
}

// safeReturnTo keeps a post-sign-in destination on our own front end: a path,
// never a URL. "//evil.example" is a URL to a browser, so it is refused too.
func safeReturnTo(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") ||
		strings.ContainsAny(p, "\r\n") || len(p) > 2048 {
		return "/"
	}
	return p
}

// sameState compares the state cookie with the state parameter in constant time.
func sameState(cookie, param string) bool {
	return cookie != "" && param != "" && subtle.ConstantTimeCompare([]byte(cookie), []byte(param)) == 1
}
