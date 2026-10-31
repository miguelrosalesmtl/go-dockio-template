package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/identity"
)

// handleListPermissions publishes the catalog, so a front end can label the keys
// døckio's role editor shows. It is the same list as in the open source code.
func (s *Server) handleListPermissions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      identity.CatalogVersion,
		"organization": identity.Catalog,
		"system":       identity.SystemCatalog,
	})
}

// ---------------------------------------------------------------- the caller

// handleMe answers who is signed in, how, and which system permissions they hold
// -- what the front end needs to show (or hide) the system pages and the
// connection warnings.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, session := userFrom(ctx), sessionFrom(ctx)
	body := map[string]any{"user": user, "auth_method": session.AuthMethod}

	perms, err := s.identity.SystemAccess(ctx, user, session)
	if err != nil {
		// "Who am I" must not fail because døckio is down; it just knows less.
		body["system_permissions"], body["dockio_unavailable"] = []string{}, true
	} else {
		body["system_permissions"] = perms
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	user, current := userFrom(r.Context()), sessionFrom(r.Context())
	sessions, err := s.identity.ListSessions(r.Context(), user.ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	type sessionView struct {
		identity.Session
		Current bool `json:"current"`
	}
	views := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		views = append(views, sessionView{Session: sess, Current: sess.ID == current.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// handleRevokeSession signs one device out. The service puts the caller's user
// id in the WHERE clause, so it cannot revoke anybody else's session.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "sessionID must be a UUID")
		return
	}
	if err := s.identity.RevokeSession(r.Context(), userFrom(r.Context()), sessionID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- organizations

// handleListOrganizations lists the organizations the caller is offered: those
// linked to a realm døckio says they are in. The front end's organization picker.
func (s *Server) handleListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.identity.ListOrganizations(r.Context(), sessionFrom(r.Context()))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

func (s *Server) handleGetOrganization(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, accessFrom(r.Context()))
}

type updateOrganizationRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	var req updateOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body (only the name can be changed; the slug is immutable)")
		return
	}
	ctx := r.Context()
	org, err := s.identity.UpdateOrganization(ctx, userFrom(ctx), accessFrom(ctx), req.Name)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (s *Server) handleDeleteOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.identity.DeleteOrganization(ctx, userFrom(ctx), accessFrom(ctx)); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- audit

const auditPageSize = 50

// handleListAuditLog lists the organization's audit trail, newest first, with
// keyset pagination (?before=<id>) and filters (?action, ?actor, ?from, ?to).
func (s *Server) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := audit.Filter{Limit: auditPageSize, Action: audit.Action(q.Get("action"))}

	if raw := q.Get("before"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be a UUID")
			return
		}
		filter.Before = parsed
	}
	if raw := q.Get("actor"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "actor must be a user UUID")
			return
		}
		filter.ActorUserID = &parsed
	}
	for _, f := range []struct {
		name string
		dest *time.Time
	}{{"from", &filter.From}, {"to", &filter.To}} {
		if raw := q.Get(f.name); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, f.name+" must be an RFC 3339 timestamp")
				return
			}
			*f.dest = parsed
		}
	}

	entries, err := audit.NewRecorder(s.pool).List(r.Context(), organizationFrom(r.Context()).ID, filter)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	var next string
	if len(entries) == auditPageSize {
		next = entries[len(entries)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "next_before": next})
}
