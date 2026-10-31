package server

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
)

// Handlers are deliberately thin: decode, call the service, encode. Every rule
// worth testing lives in internal/identity.

// ---------------------------------------------------------------- cookies

// The two round trips through døckio each park their state in a short-lived
// cookie. SameSite=Lax is what lets it come back on døckio's top-level redirect
// to us, and the path keeps it off every other request.
const (
	signinStateCookie  = "dockio_signin_state"
	connectStateCookie = "dockio_connect_state"
	stateCookieTTL     = 10 * time.Minute
)

// Secure comes from AUTH_SESSION_COOKIE_SECURE, which startup forces on in
// production; it is off only for plain-http local development.

func (s *Server) setStateCookie(w http.ResponseWriter, name, path, value string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configured; see above
		Name: name, Value: value, Path: path, MaxAge: int(stateCookieTTL.Seconds()),
		HttpOnly: true, Secure: s.cfg.Auth.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// takeStateCookie reads a state cookie and clears it: a state is good for one
// callback.
func (s *Server) takeStateCookie(w http.ResponseWriter, r *http.Request, name, path string) string {
	c, err := r.Cookie(name)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configured; see above
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.Auth.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configured; see above
		Name: s.cfg.Auth.SessionCookieName, Value: token, Path: "/", MaxAge: int(s.cfg.Auth.SessionTTL.Seconds()),
		HttpOnly: true, Secure: s.cfg.Auth.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is configured; see above
		Name: s.cfg.Auth.SessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.Auth.SessionCookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// redirectTo sends the browser to a path on the front end, with query values.
func (s *Server) redirectTo(w http.ResponseWriter, r *http.Request, path string, q url.Values) {
	target := s.cfg.Frontend.URL(path)
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// flowCode is the code to put in a redirect for err. Anything that is not a
// FlowError is logged in full and reported as a bare "internal": a redirect URL
// ends up in browser history and proxy logs, and must never carry a detail.
func (s *Server) flowCode(r *http.Request, err error) string {
	var fe *identity.FlowError
	switch {
	case errors.As(err, &fe):
		s.log.Info("døckio round trip refused", slog.String("path", r.URL.Path), slog.String("error", err.Error()))
		return fe.Code
	case errors.Is(err, identity.ErrNotFound):
		return "unknown_organization"
	case errors.Is(err, identity.ErrDockioUnavailable):
		return identity.CodeDockioUnavailable
	default:
		s.log.Error("døckio round trip failed", slog.String("path", r.URL.Path), slog.String("error", err.Error()))
		return "internal"
	}
}

// ---------------------------------------------------------------- sign-in

// handleAuthConfig tells the login page whether "Continue with døckio" can work,
// so it can say "an administrator must renew the døckio connection" instead of
// showing a button that fails.
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	ok, err := s.identity.SigninAvailable(r.Context())
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signin_available": ok, "unavailable": !ok})
}

// handleSigninStart sends the browser to døckio. ?organization=<slug> signs in to
// that organization's realm (the front end's /b/<slug> page uses it);
// ?return_to=/path is where to land afterwards.
func (s *Server) handleSigninStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, state, err := s.identity.StartSignIn(r.Context(), q.Get("organization"), q.Get("return_to"))
	if err != nil {
		s.redirectTo(w, r, s.cfg.Frontend.LoginPath, url.Values{"error": {s.flowCode(r, err)}})
		return
	}
	s.setStateCookie(w, signinStateCookie, identity.PathSigninCallback, state)
	// Not an open redirect: the target is døckio's authorization endpoint, from a
	// discovery document checked to be on the connected issuer's origin.
	http.Redirect(w, r, redirect, http.StatusFound) //nolint:gosec // see above
}

// handleSigninCallback is where døckio sends the browser back. It is public: the
// state cookie binds it to the browser that started it.
func (s *Server) handleSigninCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cookie := s.takeStateCookie(w, r, signinStateCookie, identity.PathSigninCallback)
	res, err := s.identity.CompleteSignIn(r.Context(), cookie, q.Get("state"), q.Get("code"), q.Get("error"), s.requestMeta(r))
	if err != nil {
		s.redirectTo(w, r, s.cfg.Frontend.LoginPath, url.Values{"error": {s.flowCode(r, err)}})
		return
	}
	s.setSessionCookie(w, res.Token)
	s.redirectTo(w, r, res.ReturnTo, nil)
}

// handleSignedOut is where døckio returns the browser after ending its session.
// It is on this API's origin because the manifest's URIs must be.
func (s *Server) handleSignedOut(w http.ResponseWriter, r *http.Request) {
	s.redirectTo(w, r, s.cfg.Frontend.LoginPath, url.Values{"signed_out": {"1"}})
}

// handleLogout ends the session and answers where to send the browser to end the
// døckio session too. The front end navigates there; when it is empty, it simply
// shows its signed-out page.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logoutURL, err := s.identity.SignOut(ctx, userFrom(ctx), sessionFrom(ctx))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"logout_url": logoutURL})
}

type adminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleAdminLogin is the emergency sign-in. It answers the token too, for a
// client that is not a browser.
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req adminLoginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	token, user, err := s.identity.SuperuserSignIn(r.Context(), req.Email, req.Password, s.requestMeta(r))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": user})
}

// ---------------------------------------------------------------- døckio calling us

// maxNoticeBytes caps the body døckio's notices arrive in. A logout token or a
// revocation notice is well under 4 KiB.
const maxNoticeBytes = 16 << 10

// readFormToken reads one field of a form-encoded notice, with the body capped.
func readFormToken(w http.ResponseWriter, r *http.Request, field string) string {
	r.Body = http.MaxBytesReader(w, r.Body, maxNoticeBytes)
	if err := r.ParseForm(); err != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		return ""
	}
	return r.PostForm.Get(field)
}

// handleBackchannelLogout receives døckio's signed logout token (OpenID Connect
// Back-Channel Logout: field "logout_token").
func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	err := s.identity.BackchannelLogout(r.Context(), readFormToken(w, r, "logout_token"))
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, identity.ErrInvalidNotice):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	default:
		s.errors.handle(w, r, err) // 5xx: døckio retries
	}
}

// handleConnectionRevoked receives døckio's connection-revoked notice. The field
// is "token" -- not "revocation_token".
func (s *Server) handleConnectionRevoked(w http.ResponseWriter, r *http.Request) {
	err := s.identity.ConnectionRevoked(r.Context(), readFormToken(w, r, "token"))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, identity.ErrInvalidNotice):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	default:
		s.errors.handle(w, r, err)
	}
}

// handleManifest is what døckio fetches while an operator approves a connection.
func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.identity.Manifest())
}

// ---------------------------------------------------------------- Quick connect

type connectRequest struct {
	StationURL string `json:"station_url"`
	Renew      bool   `json:"renew"`
}

// handleConnectStart begins Quick connect, renew or reconnect. The front end
// navigates to redirect_url (window.location.assign).
func (s *Server) handleConnectStart(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	redirect, state, err := s.identity.StartConnect(r.Context(), userFrom(r.Context()), req.StationURL, req.Renew)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.setStateCookie(w, connectStateCookie, identity.PathConnectCallback, state)
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": redirect})
}

// handleConnectCallback is where døckio returns the operator. It redirects to the
// sign-in settings page with ?connected=1, ?renewed=1 or ?connect_error=<code>.
func (s *Server) handleConnectCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cookie := s.takeStateCookie(w, r, connectStateCookie, identity.PathConnectCallback)
	res, err := s.identity.CompleteConnect(r.Context(), cookie, q.Get("state"), q.Get("code"), q.Get("error"))
	if err != nil {
		s.redirectTo(w, r, s.cfg.Frontend.SigninSettingsPath, url.Values{"connect_error": {s.flowCode(r, err)}})
		return
	}
	s.redirectTo(w, r, s.cfg.Frontend.SigninSettingsPath, url.Values{string(res): {"1"}})
}

func (s *Server) handleGetConnection(w http.ResponseWriter, r *http.Request) {
	v, err := s.identity.Connection(r.Context())
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	told, err := s.identity.Disconnect(r.Context(), userFrom(r.Context()))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"dockio_told": told})
}

type manualConnectionRequest struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (s *Server) handleSaveManualConnection(w http.ResponseWriter, r *http.Request) {
	var req manualConnectionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.identity.SaveManualConnection(r.Context(), userFrom(r.Context()), req.Issuer, req.ClientID, req.ClientSecret); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.handleGetConnection(w, r)
}

type setSigninEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSetSigninEnabled(w http.ResponseWriter, r *http.Request) {
	var req setSigninEnabledRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.identity.SetSigninEnabled(r.Context(), userFrom(r.Context()), req.Enabled); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.handleGetConnection(w, r)
}

func (s *Server) handleSyncCatalog(w http.ResponseWriter, r *http.Request) {
	if err := s.identity.SyncCatalog(r.Context()); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	s.handleGetConnection(w, r)
}
