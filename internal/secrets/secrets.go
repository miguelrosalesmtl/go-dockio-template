// Package secrets seals the few values the application must be able to read back
// but must never store in the clear: the døckio client secret, the PKCE verifiers
// of in-flight sign-in and connect attempts, and id tokens kept for sign-out.
//
// A password or a session token is HASHED, because nobody ever needs it back.
// These are different: the server has to present them to døckio again later, so
// they are encrypted under one application key (AES-256-GCM) instead.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the length of the application key: 32 bytes, for AES-256.
const KeySize = 32

// version prefixes every sealed value. It costs one byte and buys the ability to
// change the scheme -- a new cipher, or key rotation with a key id -- without
// guessing what an old row was sealed with.
const version byte = 1

// ErrUnsealable is returned for a value that was not sealed with this key: it was
// tampered with, truncated, or sealed under a key that has since been replaced.
var ErrUnsealable = errors.New("secrets: cannot unseal -- wrong key or tampered value")

// Box seals and opens values under one key. It is safe for concurrent use.
type Box struct {
	aead cipher.AEAD
}

// New builds a Box from a raw 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return &Box{aead: aead}, nil
}

// ParseKey decodes the key as it appears in the environment: standard base64 of
// 32 random bytes, as printed by `openssl rand -base64 32`.
func ParseKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secrets: key is not base64: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

// Seal encrypts plaintext. The output is version || nonce || ciphertext+tag.
//
// The nonce is random. With 96-bit nonces that is safe for far more values than
// this application will ever seal under one key.
func (b *Box) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+b.aead.Overhead())
	out = append(out, version)
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plaintext, []byte{version}), nil
}

// Open decrypts a value produced by Seal.
func (b *Box) Open(sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < 1+n+b.aead.Overhead() || sealed[0] != version {
		return nil, ErrUnsealable
	}
	plaintext, err := b.aead.Open(nil, sealed[1:1+n], sealed[1+n:], []byte{version})
	if err != nil {
		return nil, ErrUnsealable
	}
	return plaintext, nil
}

// SealString and OpenString are the forms every caller actually wants.
func (b *Box) SealString(s string) ([]byte, error) { return b.Seal([]byte(s)) }

// OpenString is Open for a value that was a string.
func (b *Box) OpenString(sealed []byte) (string, error) {
	p, err := b.Open(sealed)
	return string(p), err
}
