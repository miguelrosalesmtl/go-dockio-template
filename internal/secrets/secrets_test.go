package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func newBox(t *testing.T) *Box {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestASealedValueOpens(t *testing.T) {
	b := newBox(t)
	sealed, err := b.SealString("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("client-secret")) {
		t.Fatal("the sealed value contains the plaintext")
	}
	got, err := b.OpenString(sealed)
	if err != nil || got != "client-secret" {
		t.Fatalf("open = %q, %v", got, err)
	}
}

func TestSealingTwiceGivesDifferentValues(t *testing.T) {
	b := newBox(t)
	x, _ := b.SealString("same")
	y, _ := b.SealString("same")
	if bytes.Equal(x, y) {
		t.Fatal("two seals of the same value are identical: the nonce is not random")
	}
}

func TestATamperedValueDoesNotOpen(t *testing.T) {
	b := newBox(t)
	sealed, _ := b.SealString("client-secret")
	sealed[len(sealed)-1] ^= 1
	if _, err := b.Open(sealed); !errors.Is(err, ErrUnsealable) {
		t.Fatalf("err = %v, want ErrUnsealable", err)
	}
}

func TestAnotherKeyCannotOpen(t *testing.T) {
	sealed, _ := newBox(t).SealString("client-secret")
	if _, err := newBox(t).Open(sealed); !errors.Is(err, ErrUnsealable) {
		t.Fatalf("err = %v, want ErrUnsealable", err)
	}
}

func TestShortOrUnversionedValuesDoNotOpen(t *testing.T) {
	b := newBox(t)
	for _, v := range [][]byte{nil, {1}, bytes.Repeat([]byte{2}, 64)} {
		if _, err := b.Open(v); !errors.Is(err, ErrUnsealable) {
			t.Fatalf("Open(%v) err = %v, want ErrUnsealable", v, err)
		}
	}
}

func TestParseKeyNeedsThirtyTwoBytes(t *testing.T) {
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("a 16-byte key was accepted")
	}
	if _, err := ParseKey("not base64!"); err == nil {
		t.Fatal("a non-base64 key was accepted")
	}
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatalf("a 32-byte key was refused: %v", err)
	}
}
