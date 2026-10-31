package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/audit"
	"github.com/miguelrosalesmtl/go-dockio-template/internal/database"
)

// orgWithHistory makes an organization with a few audit entries in it.
func (e *env) orgWithHistory() Organization {
	e.t.Helper()
	org, err := e.svc.CreateOrganization(e.ctx, e.admin, "shop", "Shop", "")
	if err != nil {
		e.t.Fatal(err)
	}
	access := OrganizationAccess{Organization: org, Permissions: AllPermissions()}
	if _, err := e.svc.UpdateOrganization(e.ctx, e.admin, access, "Shop & Co"); err != nil {
		e.t.Fatal(err)
	}
	return org
}

func TestAuditLogRefusesAccidentalTampering(t *testing.T) {
	e := newEnv(t)
	org := e.orgWithHistory()
	entries, err := audit.NewRecorder(testPool).List(e.ctx, org.ID, audit.Filter{})
	if err != nil || len(entries) == 0 {
		t.Fatalf("no audit entries to attack: %v", err)
	}
	victim := entries[0]

	// A plain UPDATE or DELETE -- the shape a bug or an injected statement takes --
	// is refused outright.
	for name, stmt := range map[string]string{
		"UPDATE": `UPDATE audit_log SET action = 'nothing.happened' WHERE id = $1`,
		"DELETE": `DELETE FROM audit_log WHERE id = $1`,
	} {
		_, err := testPool.Exec(e.ctx, stmt, victim.ID)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v, want the append-only trigger to refuse it", name, err)
		}
	}

	// A zero retention keeps everything: the default never destroys evidence.
	err = database.InTx(e.ctx, testPool, func(db database.DB) error {
		n, err := audit.NewRecorder(db).Purge(e.ctx, 0)
		if n != 0 {
			t.Errorf("a zero retention purged %d entries", n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The trigger guards against mistakes, not against an attacker who controls the
// application: the single database user can set the GUC the trigger checks. This
// test exists so that limit can never be a surprise. The README says the same.
func TestTheAppCanBypassTheAuditTriggerIfItWantsTo(t *testing.T) {
	e := newEnv(t)
	e.orgWithHistory()

	err := database.InTx(e.ctx, testPool, func(db database.DB) error {
		if _, err := db.Exec(e.ctx, `SET LOCAL app.audit_purge = 'on'`); err != nil {
			return err
		}
		_, err := db.Exec(e.ctx, `DELETE FROM audit_log`)
		return err
	})
	if err != nil {
		t.Fatalf("the bypass failed -- the guarantee is STRONGER than documented; update the docs and this test: %v", err)
	}
	if n := countAudit(t, "organizations.created"); n != 0 {
		t.Fatalf("%d entries survived", n)
	}
}

func TestAuditSearchFiltersByActionActorAndTime(t *testing.T) {
	e := newEnv(t)
	org := e.orgWithHistory()
	rec := audit.NewRecorder(testPool)

	got, err := rec.List(e.ctx, org.ID, audit.Filter{Action: audit.ActionOrganizationUpdated})
	if err != nil || len(got) != 1 {
		t.Fatalf("by action: %d entries, %v", len(got), err)
	}
	got, _ = rec.List(e.ctx, org.ID, audit.Filter{ActorUserID: &e.admin.ID})
	if len(got) < 2 {
		t.Fatalf("by actor: %d entries", len(got))
	}
	got, _ = rec.List(e.ctx, org.ID, audit.Filter{From: time.Now().Add(-2 * time.Hour), To: time.Now().Add(-time.Hour)})
	if len(got) != 0 {
		t.Fatalf("a window in the past matched %d entries", len(got))
	}
}
