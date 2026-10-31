package dockio

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// døckio's own name has an "ø" in it, so its addresses are internationalised
// domain names: https://døck.io and https://xn--dck-0na.io are the same station.
// Every comparison in this package goes through these helpers, which compare the
// ASCII (punycode) form, so neither spelling is treated as a stranger.

// ErrBadURL is wrapped by every URL this package refuses.
var ErrBadURL = errors.New("dockio: unacceptable URL")

// parse returns u with its host lower-cased and converted to ASCII.
func parse(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%w: %q is not http(s)", ErrBadURL, raw)
	}
	if u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: %q has no host, or carries credentials", ErrBadURL, raw)
	}
	host, err := idna.Lookup.ToASCII(strings.ToLower(u.Hostname()))
	if err != nil {
		return nil, fmt.Errorf("%w: host of %q: %w", ErrBadURL, raw, err)
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	return u, nil
}

// ASCIIURL returns raw with its host in punycode, ready to put on the wire.
func ASCIIURL(raw string) (string, error) {
	u, err := parse(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Origin returns scheme://host[:port] in canonical ASCII form.
func Origin(raw string) (string, error) {
	u, err := parse(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// SameOrigin reports whether a and b are on the same origin.
func SameOrigin(a, b string) bool {
	oa, err1 := Origin(a)
	ob, err2 := Origin(b)
	return err1 == nil && err2 == nil && oa == ob
}

// SameIssuer compares two issuers by origin AND path.
//
// Tenants share their station's origin -- https://døck.io/t/acme and
// https://døck.io/t/other -- so an origin-only comparison would accept a token,
// a grant or a revocation notice from the wrong tenant. Do not "simplify" this
// to SameOrigin.
func SameIssuer(a, b string) bool {
	ua, err1 := parse(a)
	ub, err2 := parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ua.Scheme == ub.Scheme && ua.Host == ub.Host &&
		strings.TrimRight(ua.Path, "/") == strings.TrimRight(ub.Path, "/")
}

// IsLoopback reports whether raw points at this machine.
func IsLoopback(raw string) bool {
	u, err := parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// CheckSecure refuses anything but https, except plain http to a loopback host --
// which is how a developer runs the app against a local døckio.
func CheckSecure(raw string) error {
	u, err := parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" || IsLoopback(raw) {
		return nil
	}
	return fmt.Errorf("%w: %q must be https (plain http is accepted only to a loopback host)", ErrBadURL, raw)
}

// CheckOnOrigin refuses an endpoint that is not on base's origin, or not secure.
//
// This is what stops a hostile discovery document from steering the browser to
// one place and the client secret to another.
func CheckOnOrigin(base, endpoint string) error {
	if err := CheckSecure(endpoint); err != nil {
		return err
	}
	if !SameOrigin(base, endpoint) {
		return fmt.Errorf("%w: %q is not on the origin of %q", ErrBadURL, endpoint, base)
	}
	return nil
}
