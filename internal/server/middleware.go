package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/auth"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
)

// withAuditMeta attaches the request id, client IP, and user agent to the context,
// so every audit entry written while serving this request carries them.
//
// It sits at the top of the chain, before authentication, precisely because the
// entries that most need it are the ones written when authentication FAILS.
func (s *Server) withAuditMeta(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := audit.RequestMeta{
			RequestID: middleware.GetReqID(r.Context()),
			IPAddress: s.clientIP(r),
			UserAgent: r.UserAgent(),
		}
		next.ServeHTTP(w, r.WithContext(audit.WithRequestMeta(r.Context(), meta)))
	})
}

// requireAuth authenticates the caller and puts the acting user on the request
// context. Everything behind it can call userFrom(ctx) unconditionally.
//
// It accepts three credentials:
//
//   - the session cookie: how the browser front end authenticates. The cookie
//     names a server-side session; the browser never holds a døckio token.
//   - a session token as a bearer (sess_...): the same session, for a client that
//     is not a browser -- and what the emergency sign-in returns.
//   - an API key as a bearer (key_...): belongs to an organization, carries its
//     own frozen scope, and acts as its creating user. sessionOnly keeps it off
//     everything but organization routes.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, fromCookie := bearerToken(r), false
		if token == "" {
			if c, err := r.Cookie(s.cfg.Auth.SessionCookieName); err == nil {
				token, fromCookie = c.Value, true
			}
		}
		if token == "" {
			s.errors.handle(w, r, identity.ErrUnauthenticated)
			return
		}

		if !fromCookie && strings.HasPrefix(token, auth.APIKeyTokenPrefix) {
			key, org, actor, err := s.identity.AuthenticateAPIKey(r.Context(), token)
			if err != nil {
				s.errors.handle(w, r, err)
				return
			}
			ctx := withUser(r.Context(), actor, identity.Session{})
			ctx = withAPIKey(ctx, apiKeyContext{key: key, org: org})
			// Re-stamp the audit metadata to tag every entry with the key id.
			ctx = audit.WithRequestMeta(ctx, audit.RequestMeta{
				RequestID: middleware.GetReqID(ctx),
				IPAddress: s.clientIP(r),
				UserAgent: r.UserAgent(),
				APIKeyID:  &key.ID,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		user, session, err := s.identity.Authenticate(r.Context(), token)
		if err != nil {
			if fromCookie {
				s.clearSessionCookie(w) // a dead cookie is just noise on every request
			}
			s.errors.handle(w, r, err)
			return
		}
		ctx := withUser(r.Context(), user, session)
		if fromCookie {
			ctx = withCookieAuth(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrf protects cookie-authenticated requests that change something.
//
// A cookie is sent by the browser on its own, including on a request another site
// triggers -- that is cross-site request forgery. A bearer token is not, so only
// cookie-authenticated requests need this. They must carry the header
// X-CSRF-Protection: 1. A plain HTML form cannot set a custom header, and a script
// on another origin can only do so after a CORS preflight that this API refuses
// unless the origin is on the allowlist.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if cookieAuth(r.Context()) && r.Header.Get(csrfHeader) != "1" {
				writeError(w, http.StatusForbidden, "missing "+csrfHeader+": 1 on a cookie-authenticated request")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// csrfHeader is the header a browser front end sends on every state-changing call.
const csrfHeader = "X-CSRF-Protection"

// sessionOnly rejects API-key credentials: account management and the system
// surface are for people, never for a key scoped to one organization.
func (s *Server) sessionOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := apiKeyFrom(r.Context()); ok {
			writeError(w, http.StatusForbidden,
				"API keys cannot be used on this endpoint; authenticate with a user session")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireOrganization resolves the {organization} slug, asks whether the caller
// may act in it, and puts the organization and their permissions on the context.
//
// This is the single choke point for organization authorization: every route
// under /api/v1/organizations/{organization} passes through it.
func (s *Server) requireOrganization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "organization")

		// An API key acts only on its own organization; anything else is 404, the
		// same answer a stranger gets. Its authority is its frozen scope.
		if kc, ok := apiKeyFrom(r.Context()); ok {
			if slug != kc.org.Slug {
				s.errors.handle(w, r, identity.ErrNotFound)
				return
			}
			access := identity.OrganizationAccess{Organization: kc.org, Permissions: kc.key.Permissions, ViaAPIKey: true}
			next.ServeHTTP(w, r.WithContext(withOrganization(r.Context(), access)))
			return
		}

		user := userFrom(r.Context())
		access, err := s.identity.ResolveOrganization(r.Context(), user, sessionFrom(r.Context()), slug)
		if err != nil {
			s.errors.handle(w, r, err)
			return
		}

		// The superuser bypass is allowed only because it cannot happen unseen: the
		// audit entry is written BEFORE serving, and a failure to write it refuses
		// the request.
		if access.ViaSuperuser {
			if err := s.identity.RecordSuperuserAccess(r.Context(), user, access.Organization, r.Method, r.URL.Path); err != nil {
				s.log.Error("could not audit superuser organization access -- refusing the request",
					slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
				s.errors.handle(w, r, err)
				return
			}
			s.log.Warn("superuser entered an organization through the bypass",
				slog.String("user_id", user.ID.String()), slog.String("organization", access.Organization.Slug),
				slog.String("method", r.Method), slog.String("path", r.URL.Path))
		}
		next.ServeHTTP(w, r.WithContext(withOrganization(r.Context(), access)))
	})
}

// requireSystem guards the system surface with one system permission. Without it
// the answer is 404: the surface does not advertise itself.
func (s *Server) requireSystem(p identity.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms, err := s.identity.SystemAccess(r.Context(), userFrom(r.Context()), sessionFrom(r.Context()))
			if err != nil {
				s.errors.handle(w, r, err)
				return
			}
			if !perms.Has(p) {
				s.errors.handle(w, r, identity.ErrNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requirePermission rejects callers who lack permission p in the request's
// organization. It must sit inside requireOrganization.
//
// The permission must exist in identity.Catalog. A route guarded by a permission
// you forgot to add there is never published to døckio, so no role can grant it,
// and the route becomes reachable only through the superuser bypass. That is a
// loud failure by design.
func (s *Server) requirePermission(p identity.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !accessFrom(r.Context()).Can(p) {
				s.errors.handle(w, r, identity.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken pulls the credential out of the Authorization header. The scheme
// match is case-insensitive because RFC 7235 says it is.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// clientIP returns the caller's IP for the session and audit records.
//
// X-Forwarded-For is honoured only when SERVER_TRUST_PROXY_HEADERS is on. The
// header is trivially forged by anyone talking to the server directly, so
// trusting it unconditionally would let a caller write whatever IP they liked
// into the audit log -- which is worse than having no IP at all. Turn it on only
// when a proxy you control is guaranteed to overwrite the header.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.Server.TrustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// The left-most entry is the original client; the rest are the proxies
			// it passed through.
			first, _, _ := strings.Cut(fwd, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			return real
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // no port, e.g. a unix socket
	}
	return host
}

// requestMeta bundles what the service records about the caller of a request.
func (s *Server) requestMeta(r *http.Request) identity.RequestMeta {
	// Cap the User-Agent: it is attacker-controlled and goes straight into a text
	// column, and nobody needs 8KB of it.
	ua := r.UserAgent()
	if len(ua) > 512 {
		ua = ua[:512]
	}
	return identity.RequestMeta{UserAgent: ua, IPAddress: s.clientIP(r)}
}

// requestLogger logs one line per request. It deliberately never logs the
// Authorization header, the request body, or the query string -- all three
// routinely carry credentials.
func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			log.Info("request",
				slog.String("method", r.Method),
				// r.URL.Path, not RequestURI: the query string may hold a token.
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", middleware.GetReqID(r.Context())),
			)
		})
	}
}

// statusRecorder captures the status code so the logger can report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
