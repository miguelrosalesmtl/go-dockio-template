package dockio

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrInvalidToken wraps every reason a JWT is refused. A station that cannot be
// reached to fetch its keys is NOT an invalid token -- that is ErrUnavailable --
// so an outage never reads as "this person's credentials are bad".
var ErrInvalidToken = errors.New("dockio: invalid token")

func invalidToken(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, args...))
}

// leeway is the clock skew tolerated on exp and iat.
const leeway = 30 * time.Second

// jwsHeader is the protected header of a compact JWS.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// registeredClaims are the claims every token checked here carries.
type registeredClaims struct {
	Iss string          `json:"iss"`
	Aud json.RawMessage `json:"aud"`
	Sub string          `json:"sub"`
	Iat *int64          `json:"iat"`
	Exp *int64          `json:"exp"`
	Jti string          `json:"jti"`
}

// audienceIs reports whether aud -- a string, or an array of strings -- names id.
func (c registeredClaims) audienceIs(id string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == id
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == id {
				return true
			}
		}
	}
	return false
}

// checkTimes enforces exp in the future and iat not in the future, both within
// the leeway, and requires both to be present.
func (c registeredClaims) checkTimes(now time.Time) error {
	if c.Exp == nil || c.Iat == nil {
		return invalidToken("exp and iat are required")
	}
	if now.After(time.Unix(*c.Exp, 0).Add(leeway)) {
		return invalidToken("expired")
	}
	if time.Unix(*c.Iat, 0).After(now.Add(leeway)) {
		return invalidToken("issued in the future")
	}
	return nil
}

// keySet fetches and caches a station's signing keys by kid.
//
// An unknown kid triggers at most one refetch per refetchEvery: a key rotation is
// picked up on its first token, and a flood of tokens with made-up kids cannot
// turn the application into a request amplifier against the station.
type keySet struct {
	url  string
	http *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

const refetchEvery = 30 * time.Second

func newKeySet(url string, hc *http.Client) *keySet {
	return &keySet{url: url, http: hc, keys: map[string]*rsa.PublicKey{}}
}

func (k *keySet) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	if !k.lastFetch.IsZero() && time.Since(k.lastFetch) < refetchEvery {
		return nil, invalidToken("unknown key id %q", kid)
	}
	keys, err := fetchJWKS(ctx, k.http, k.url)
	if err != nil {
		return nil, err
	}
	k.keys, k.lastFetch = keys, time.Now()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	return nil, invalidToken("unknown key id %q", kid)
}

func fetchJWKS(ctx context.Context, hc *http.Client, url string) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := getJSON(ctx, hc, url, &doc); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range doc.Keys {
		if j.Kty != "RSA" || (j.Use != "" && j.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(j.N)
		e, err2 := base64.RawURLEncoding.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		var exp int
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		keys[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	}
	return keys, nil
}

// verifyJWS checks a compact RS256 JWS and decodes its claims into out. It
// checks the algorithm, the typ (when wantTyp is set), the key and the signature;
// the caller checks the claims, because which claims matter depends on the token.
//
// wantTyp "" accepts a missing typ or "JWT" -- what an id token carries.
func (k *keySet) verifyJWS(ctx context.Context, token, wantTyp string, out any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return invalidToken("not a compact JWS")
	}
	var h jwsHeader
	if err := decodeSegment(parts[0], &h); err != nil {
		return invalidToken("header: %v", err)
	}
	if h.Alg != "RS256" {
		return invalidToken("alg %q, want RS256", h.Alg)
	}
	switch {
	case wantTyp == "" && h.Typ != "" && h.Typ != "JWT":
		return invalidToken("typ %q on what should be an id token", h.Typ)
	case wantTyp != "" && h.Typ != wantTyp:
		return invalidToken("typ %q, want %q", h.Typ, wantTyp)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return invalidToken("signature encoding")
	}
	key, err := k.key(ctx, h.Kid)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return invalidToken("bad signature")
	}
	if err := decodeSegment(parts[1], out); err != nil {
		return invalidToken("claims: %v", err)
	}
	return nil
}

func decodeSegment(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
