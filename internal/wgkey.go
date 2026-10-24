package internal

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateWgKeypair generates a WireGuard curve25519 key pair and returns it
// as two base64 (standard encoding) strings.
//
// The private key is clamped the same way the official wg tool clamps it:
// the low three bits of the first byte are cleared, the high bit of the last
// byte is cleared and the second-highest bit is set. Cloudflare's /reg
// endpoint only checks the shape of the key, but the resulting key must work
// with a standard WireGuard peer, so the clamping matters.
//
// Returns:
//   - privB64: The base64-encoded 32-byte private key.
//   - pubB64:  The base64-encoded 32-byte public key.
//   - error:   An error if random data generation or X25519 fails.
func GenerateWgKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err = rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("failed to read random bytes: %v", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}
