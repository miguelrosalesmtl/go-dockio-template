package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio"
)

// Permissions are defined HERE, in code. døckio stores the roles and who holds
// them, but it never invents a key: the application publishes this catalog to
// døckio (the "catalog sync"), and døckio's role editor offers exactly these.
//
// There are two kinds:
//
//   - Organization permissions, checked inside one organization. Published as
//     "<app_key>:biz:<resource>:<level>" and granted by roles in that
//     organization's døckio realm.
//   - System permissions, for the operator's own staff, checked outside any
//     organization. Published as "<app_key>:system:<capability>" and granted in
//     the home realm.
//
// Inside the code a permission is written "resource.level" ("apikeys.create").
// WireKey is the one place that maps it to døckio's form.

// Permission is one thing a caller may be allowed to do.
type Permission string

// Organization permissions. Add your own resources here -- and bump
// CatalogVersion -- as you build the application.
const (
	PermOrganizationRead   Permission = "organization.read"
	PermOrganizationUpdate Permission = "organization.update" // the name; the slug is immutable
	PermOrganizationDelete Permission = "organization.delete" // soft delete -- restorable by a superuser

	PermAuditRead Permission = "audit.read"

	PermAPIKeysRead   Permission = "apikeys.read"
	PermAPIKeysCreate Permission = "apikeys.create"
	PermAPIKeysDelete Permission = "apikeys.delete"
)

// System permissions.
const (
	// PermSystemSignin manages the døckio connection: Quick connect, renew,
	// disconnect, manual setup, and turning sign-in on and off.
	PermSystemSignin Permission = "system.signin"
	// PermSystemOrganizations creates organizations, links them to realms, and
	// lists or restores them across the installation.
	PermSystemOrganizations Permission = "system.organizations"
	// PermSystemUsers lists every user and deactivates or reactivates them.
	PermSystemUsers Permission = "system.users"
	// PermSystemSuperuser enters every organization holding every permission,
	// audited on every request -- the døckio-side equivalent of the local
	// superuser.
	PermSystemSuperuser Permission = "system.superuser"
)

// CatalogVersion must be bumped on EVERY change to Catalog or SystemCatalog.
// døckio refuses an older version than the one it holds, which is how a rolled
// back deploy is noticed rather than silently un-publishing keys.
const CatalogVersion uint64 = 1

// CatalogEntry documents one permission.
type CatalogEntry struct {
	Key         Permission `json:"key"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
}

// Catalog is every organization permission this build enforces.
var Catalog = []CatalogEntry{
	{PermOrganizationRead, "View the organization", "View the organization and its settings"},
	{PermOrganizationUpdate, "Rename the organization", "Change the organization's name"},
	{PermOrganizationDelete, "Delete the organization", "Delete the organization (a superuser can restore it)"},

	{PermAuditRead, "Read the audit log", "Read the organization's audit log"},

	{PermAPIKeysRead, "View API keys", "View the organization's API keys"},
	{PermAPIKeysCreate, "Create API keys", "Create API keys, up to the creator's own permissions"},
	{PermAPIKeysDelete, "Revoke API keys", "Revoke the organization's API keys"},
}

// SystemCatalog is every system permission this build enforces.
var SystemCatalog = []CatalogEntry{
	{PermSystemSignin, "Manage sign-in", "Connect, renew and disconnect the døckio connection"},
	{PermSystemOrganizations, "Manage organizations", "Create organizations, link them to realms, restore them"},
	{PermSystemUsers, "Manage users", "List users and deactivate or reactivate them"},
	{PermSystemSuperuser, "Superuser", "Enter every organization with every permission (audited)"},
}

// Valid reports whether p is an organization permission this build enforces.
func (p Permission) Valid() bool {
	return slices.ContainsFunc(Catalog, func(e CatalogEntry) bool { return e.Key == p })
}

// IsSystem reports whether p is a system permission.
func (p Permission) IsSystem() bool { return strings.HasPrefix(string(p), "system.") }

// WireKey is p as døckio knows it.
func (p Permission) WireKey(appKey string) string {
	if rest, ok := strings.CutPrefix(string(p), "system."); ok {
		return appKey + ":system:" + strings.ReplaceAll(rest, ".", ":")
	}
	return appKey + ":biz:" + strings.ReplaceAll(string(p), ".", ":")
}

// fromWireKeys maps døckio keys back onto this build's catalog. Keys this build
// does not know -- another application's, or a permission since removed -- are
// dropped: nothing would check them.
func fromWireKeys(appKey string, keys []string, catalog []CatalogEntry) PermissionSet {
	byWire := make(map[string]Permission, len(catalog))
	for _, e := range catalog {
		byWire[e.Key.WireKey(appKey)] = e.Key
	}
	set := PermissionSet{}
	for _, k := range keys {
		if p, ok := byWire[k]; ok {
			set[p] = struct{}{}
		}
	}
	return set
}

// DockioCatalog is the catalog as published to døckio.
func DockioCatalog(appKey string) dockio.Catalog {
	out := dockio.Catalog{Version: CatalogVersion}
	add := func(entries []CatalogEntry, category func(Permission) string) {
		for _, e := range entries {
			out.Permissions = append(out.Permissions, dockio.Permission{
				Key: e.Key.WireKey(appKey), Name: e.Name, Description: e.Description, Category: category(e.Key),
			})
		}
	}
	resource := func(p Permission) string {
		r, _, _ := strings.Cut(string(p), ".")
		return strings.ToUpper(r[:1]) + r[1:]
	}
	add(Catalog, resource)
	add(SystemCatalog, func(Permission) string { return "System" })
	return out
}

// ---------------------------------------------------------------- sets

// PermissionSet is a set of permissions.
type PermissionSet map[Permission]struct{}

// NewPermissionSet builds a set from a list.
func NewPermissionSet(perms ...Permission) PermissionSet {
	set := make(PermissionSet, len(perms))
	for _, p := range perms {
		set[p] = struct{}{}
	}
	return set
}

// AllPermissions is every organization permission -- what a superuser holds.
func AllPermissions() PermissionSet {
	set := make(PermissionSet, len(Catalog))
	for _, e := range Catalog {
		set[e.Key] = struct{}{}
	}
	return set
}

// AllSystemPermissions is every system permission -- what a local superuser holds.
func AllSystemPermissions() PermissionSet {
	set := make(PermissionSet, len(SystemCatalog))
	for _, e := range SystemCatalog {
		set[e.Key] = struct{}{}
	}
	return set
}

// Has reports whether the set grants p.
//
// IMPLICATION LIVES HERE, AND ONLY HERE: holding any other level of a resource
// ("apikeys.create") implies its "read". Roles in døckio still hold explicit keys,
// so they stay readable in døckio's console; this rule only saves a role editor
// from having to remember to tick "read" next to "write".
func (s PermissionSet) Has(p Permission) bool {
	if _, ok := s[p]; ok {
		return true
	}
	resource, level, ok := strings.Cut(string(p), ".")
	if !ok || level != "read" || resource == "system" {
		return false
	}
	for q := range s {
		if strings.HasPrefix(string(q), resource+".") {
			return true
		}
	}
	return false
}

// Superset reports whether s grants every permission in other.
func (s PermissionSet) Superset(other PermissionSet) bool {
	for p := range other {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

// Missing returns the permissions in other that s does not grant, sorted.
func (s PermissionSet) Missing(other PermissionSet) []Permission {
	var out []Permission
	for p := range other {
		if !s.Has(p) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Slice returns the set as a sorted slice.
func (s PermissionSet) Slice() []Permission {
	out := make([]Permission, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// MarshalJSON renders the set as a sorted array.
func (s PermissionSet) MarshalJSON() ([]byte, error) {
	perms := s.Slice()
	if perms == nil {
		perms = []Permission{}
	}
	return json.Marshal(perms)
}

// checkEscalation refuses to let actor grant anything they do not hold.
//
// It guards every path by which a permission can travel from the application to
// a credential: today, minting an API key. The error names what was missing.
func checkEscalation(actor OrganizationAccess, granting PermissionSet) error {
	if actor.Permissions.Superset(granting) {
		return nil
	}
	missing := actor.Permissions.Missing(granting)
	names := make([]string, 0, len(missing))
	for _, p := range missing {
		names = append(names, string(p))
	}
	return fmt.Errorf("%w: you do not hold %s", ErrEscalation, strings.Join(names, ", "))
}

// ---------------------------------------------------------------- local mirror

// SyncPermissions mirrors Catalog into the permissions table at startup.
//
// The table exists for one reason: api_key_permissions references it, so the
// database itself refuses an API key scoped to a permission no code enforces.
// Rows the code no longer has are kept and logged -- a key may still carry them.
func (s *Service) SyncPermissions(ctx context.Context) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		for _, e := range Catalog {
			_, err := db.Exec(ctx,
				`INSERT INTO permissions (key, description)
				 VALUES ($1, $2)
				 ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description`,
				e.Key, e.Description,
			)
			if err != nil {
				return fmt.Errorf("identity: sync permission %q: %w", e.Key, err)
			}
		}

		rows, err := db.Query(ctx, `SELECT key FROM permissions ORDER BY key`)
		if err != nil {
			return fmt.Errorf("identity: read permission catalog: %w", err)
		}
		defer rows.Close()

		var stale []string
		for rows.Next() {
			var key Permission
			if err := rows.Scan(&key); err != nil {
				return fmt.Errorf("identity: scan permission: %w", err)
			}
			if !key.Valid() {
				stale = append(stale, string(key))
			}
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("identity: iterate permissions: %w", err)
		}
		if len(stale) > 0 {
			s.log.Warn("the database has permissions this build does not enforce -- API keys may still carry them, and nothing will check them",
				slog.Any("stale_permissions", stale))
		}
		return nil
	})
}
