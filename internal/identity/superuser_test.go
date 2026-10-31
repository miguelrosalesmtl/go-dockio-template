package identity

import (
	"errors"
	"testing"
)

func TestTheSuperuserSignsInWithAPassword(t *testing.T) {
	e := newEnv(t)
	token, user, err := e.svc.SuperuserSignIn(e.ctx, "ROOT@example.com ", testPassword, RequestMeta{})
	if err != nil || user.ID != e.admin.ID {
		t.Fatalf("sign in: %v", err)
	}
	if _, sess := e.session(token); sess.AuthMethod != AuthMethodPassword {
		t.Fatalf("auth method = %q", sess.AuthMethod)
	}
	for _, tc := range [][2]string{{"root@example.com", "wrong-password-entirely"}, {"nobody@example.com", testPassword}} {
		if _, _, err := e.svc.SuperuserSignIn(e.ctx, tc[0], tc[1], RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: %v, want ErrInvalidCredentials", tc[0], err)
		}
	}
	if countAudit(t, "users.login_failed") != 2 {
		t.Fatal("failed sign-ins were not audited")
	}
}

func TestADockioAccountCanNeverSignInWithAPassword(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.station.SignIn = &ana
	res, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}
	// Nothing in the application can give a døckio account a password: the
	// database refuses it outright.
	_, err = testPool.Exec(e.ctx, `UPDATE users SET password_hash = 'x' WHERE id = $1`, res.User.ID)
	if err == nil {
		t.Fatal("the database let a døckio account have a password")
	}
	if _, _, err := e.svc.SuperuserSignIn(e.ctx, "ana@example.com", testPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestSettingANewPasswordEndsTheOldSessions(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.svc.SuperuserSignIn(e.ctx, "root@example.com", testPassword, RequestMeta{})
	if _, created, err := e.svc.CreateSuperuser(e.ctx, "root@example.com", "another-long-password-here"); err != nil || created {
		t.Fatalf("reset: created=%v err=%v", created, err)
	}
	if _, _, err := e.svc.Authenticate(e.ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("a session on the old password survived")
	}
	if _, _, err := e.svc.CreateSuperuser(e.ctx, "x@example.com", "short"); !errors.Is(err, ErrValidation) {
		t.Fatalf("short password: %v", err)
	}
}

func TestAPIKeysCannotOutrankTheirCreator(t *testing.T) {
	e := newEnv(t)
	user, sess := e.anaIn()
	e.station.SetEffective("ana", "r-shop", wire(PermAPIKeysCreate), wire(PermAuditRead))
	access, err := e.svc.ResolveOrganization(e.ctx, user, sess, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateAPIKey(e.ctx, user, access, "reporting", []Permission{PermAuditRead}, nil); err != nil {
		t.Fatalf("within her permissions: %v", err)
	}
	if _, _, err := e.svc.CreateAPIKey(e.ctx, user, access, "too much", []Permission{PermOrganizationDelete}, nil); !errors.Is(err, ErrEscalation) {
		t.Fatalf("err = %v, want ErrEscalation", err)
	}
}
