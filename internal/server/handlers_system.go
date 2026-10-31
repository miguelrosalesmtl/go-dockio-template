package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// The system surface: the operator's own staff, across every organization. Each
// route group requires one system permission (see routes()).

// pageBefore reads the keyset cursor (?before=<uuid>).
func pageBefore(r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return uuid.Nil, true
	}
	parsed, err := uuid.Parse(raw)
	return parsed, err == nil
}

const systemPageSize = 50

func (s *Server) handleSystemListOrganizations(w http.ResponseWriter, r *http.Request) {
	before, ok := pageBefore(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "before must be a UUID")
		return
	}
	orgs, err := s.identity.ListAllOrganizations(r.Context(), before, systemPageSize)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	var next string
	if len(orgs) == systemPageSize {
		next = orgs[len(orgs)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs, "next_before": next})
}

type systemCreateOrganizationRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	DockioRealm string `json:"dockio_realm"`
}

// handleSystemCreateOrganization creates an organization, optionally linked to
// the døckio realm that holds its people.
func (s *Server) handleSystemCreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req systemCreateOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	org, err := s.identity.CreateOrganization(r.Context(), userFrom(r.Context()), req.Slug, req.Name, req.DockioRealm)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

type setRealmRequest struct {
	DockioRealm string `json:"dockio_realm"`
}

// handleSystemSetRealm links an organization to a døckio realm ("" unlinks it).
func (s *Server) handleSystemSetRealm(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "organizationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "organizationID must be a UUID")
		return
	}
	var req setRealmRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	org, err := s.identity.SetOrganizationRealm(r.Context(), userFrom(r.Context()), id, req.DockioRealm)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

type restoreOrganizationRequest struct {
	Slug string `json:"slug"`
}

func (s *Server) handleSystemRestoreOrganization(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "organizationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "organizationID must be a UUID")
		return
	}
	var req restoreOrganizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	org, err := s.identity.RestoreOrganization(r.Context(), userFrom(r.Context()), id, req.Slug)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (s *Server) handleSystemListUsers(w http.ResponseWriter, r *http.Request) {
	before, ok := pageBefore(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "before must be a UUID")
		return
	}
	users, err := s.identity.ListAllUsers(r.Context(), before, systemPageSize)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	var next string
	if len(users) == systemPageSize {
		next = users[len(users)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "next_before": next})
}

type setUserActiveRequest struct {
	IsActive bool `json:"is_active"`
}

// handleSystemSetUserActive deactivates or reactivates a user. Deactivation ends
// every session they hold, at once.
func (s *Server) handleSystemSetUserActive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "userID must be a UUID")
		return
	}
	var req setUserActiveRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	user, err := s.identity.SetUserActive(r.Context(), userFrom(r.Context()), id, req.IsActive)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}
