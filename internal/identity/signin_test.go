package identity

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/miguelrosalesmtl/go-dockio-template/internal/dockio/dockiotest"
)

var ana = dockiotest.Person{
	UID: "u-ana", Username: "ana", Email: "ana@example.com", GivenName: "Ana", FamilyName: "Ruiz",
	Realms: []string{"r-shop"},
}

func TestSignInCreatesALinkedUserAndASession(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.station.SignIn = &ana

	res, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}
	if res.ReturnTo != "/dashboard" || res.User.Email != "ana@example.com" || res.User.IsSuperuser {
		t.Fatalf("result = %+v", res)
	}
	user, sess := e.session(res.Token)
	if user.ID != res.User.ID || sess.AuthMethod != AuthMethodDockio || sess.DockioUID != "u-ana" ||
		!slices.Contains(sess.DockioRealms, "r-shop") || len(sess.IDTokenEnc) == 0 {
		t.Fatalf("session = %+v", sess)
	}
}

func TestAccountsAreLinkedByUIDNotByUsernameOrEmail(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.station.SignIn = &ana
	first, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}

	// Ana renames herself and changes her email in døckio: same uid, same user.
	renamed := ana
	renamed.Username, renamed.Email = "ana.r", "ana.r@example.com"
	e.station.SignIn = &renamed
	second, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}
	if second.User.ID != first.User.ID || second.User.Email != "ana.r@example.com" {
		t.Fatalf("a rename made a second user, or the copy was not refreshed: %+v", second.User)
	}

	// Somebody else takes Ana's old username and email: a different person.
	impostor := dockiotest.Person{UID: "u-other", Username: "ana", Email: "ana@example.com"}
	e.station.SignIn = &impostor
	third, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}
	if third.User.ID == first.User.ID {
		t.Fatal("a different uid was linked to Ana's user through her old username or email")
	}
}

func TestSignInIsRefusedWhileOffOrExpired(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.svc.StartSignIn(e.ctx, "", "/"); flowCode(err) != CodeSigninUnavailable {
		t.Fatalf("not connected: %v", err)
	}
	c := e.connected()
	if err := e.svc.SetSigninEnabled(e.ctx, e.admin, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.StartSignIn(e.ctx, "", "/"); flowCode(err) != CodeSigninUnavailable {
		t.Fatalf("off: %v", err)
	}
	if err := e.svc.SetSigninEnabled(e.ctx, e.admin, true); err != nil {
		t.Fatal(err)
	}

	// Expired at døckio while the person was signing in: the token endpoint says
	// so, and it is reported as expired, not as a bad secret.
	e.station.SignIn = &ana
	redirect, state, err := e.svc.StartSignIn(e.ctx, "", "/")
	if err != nil {
		t.Fatal(err)
	}
	q := browse(t, redirect)
	e.station.ExpireClient(c.ClientID)
	if _, err := e.svc.CompleteSignIn(e.ctx, state, q.Get("state"), q.Get("code"), "", RequestMeta{}); flowCode(err) != CodeConnectionExpired {
		t.Fatalf("expired: %v, want connection_expired", err)
	}
}

func TestABusinessSignInMustComeBackForThatRealm(t *testing.T) {
	e := newEnv(t)
	e.connected()
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "shop", "Shop", "r-shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "bakery", "Bakery", "r-bakery"); err != nil {
		t.Fatal(err)
	}
	e.station.SignIn = &ana

	if _, err := e.signIn("shop"); err != nil {
		t.Fatalf("Ana into her own shop: %v", err)
	}
	// Ana is not in the bakery's realm: døckio refuses her there.
	if _, err := e.signIn("bakery"); flowCode(err) != CodeAccessDenied {
		t.Fatalf("Ana into the bakery: %v, want access_denied", err)
	}
	// An organization with no realm cannot be signed in to at all.
	if _, err := e.svc.CreateOrganization(e.ctx, e.admin, "unlinked", "Unlinked", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.StartSignIn(e.ctx, "unlinked", "/"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unlinked: %v, want ErrNotFound", err)
	}
}

func TestADeactivatedUserCannotSignIn(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.station.SignIn = &ana
	res, err := e.signIn("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetUserActive(e.ctx, e.admin, res.User.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(e.ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("deactivating did not end the existing session")
	}
	if _, err := e.signIn(""); flowCode(err) != CodeAccountDeactivated {
		t.Fatalf("err = %v, want account_deactivated", err)
	}
}

func TestReturnToStaysOnOurFrontEnd(t *testing.T) {
	for in, want := range map[string]string{
		"/orders?x=1":            "/orders?x=1",
		"https://evil.example/":  "/",
		"//evil.example/":        "/",
		"/\\evil.example":        "/",
		"orders":                 "/",
		"/ok\r\nSet-Cookie: x=y": "/",
	} {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignOutEndsTheSessionAndPointsAtDockio(t *testing.T) {
	e := newEnv(t)
	e.connected()
	e.station.SignIn = &ana
	res, _ := e.signIn("")
	user, sess := e.session(res.Token)

	logoutURL, err := e.svc.SignOut(e.ctx, user, sess)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(logoutURL, e.station.URL+"/end-session?") || !strings.Contains(logoutURL, "id_token_hint=") {
		t.Fatalf("logout url = %q", logoutURL)
	}
	if _, _, err := e.svc.Authenticate(e.ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("the session survived sign-out")
	}
}

func TestBackchannelLogoutEndsOneDockioSession(t *testing.T) {
	e := newEnv(t)
	c := e.connected()
	e.station.SignIn = &ana
	first, _ := e.signIn("")
	second, _ := e.signIn("")
	_, firstSess := e.session(first.Token)

	tok := e.station.SignLogout(c.ClientID, map[string]any{"sub": "ana", "uid": "u-ana", "sid": firstSess.DockioSID})
	if err := e.svc.BackchannelLogout(e.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(e.ctx, first.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("the named døckio session survived")
	}
	if _, _, err := e.svc.Authenticate(e.ctx, second.Token); err != nil {
		t.Fatal("another døckio session was ended too")
	}

	// Without a sid: every session of the account.
	tok = e.station.SignLogout(c.ClientID, map[string]any{"sub": "ana", "uid": "u-ana"})
	if err := e.svc.BackchannelLogout(e.ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Authenticate(e.ctx, second.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("an account-wide logout left a session")
	}
	// A forged token changes nothing.
	if err := e.svc.BackchannelLogout(e.ctx, "a.b.c"); !errors.Is(err, ErrInvalidNotice) {
		t.Fatalf("forged: %v", err)
	}
}

func TestARealmScopedLogoutOnlyDropsThatRealm(t *testing.T) {
	e := newEnv(t)
	c := e.connected()
	both := ana
	both.Realms = []string{"r-shop", "r-bakery"}
	e.station.SignIn = &both
	res, _ := e.signIn("")

	tok := e.station.SignLogout(c.ClientID, map[string]any{"sub": "ana", "uid": "u-ana", "dockio_realm": "r-bakery"})
	if err := e.svc.BackchannelLogout(e.ctx, tok); err != nil {
		t.Fatal(err)
	}
	_, sess := e.session(res.Token)
	if !slices.Equal(sess.DockioRealms, []string{"r-shop"}) {
		t.Fatalf("realms = %v, want only r-shop left", sess.DockioRealms)
	}
}
