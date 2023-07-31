package crv

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
)

func Curve25519() *curve25519_t { return _curve25519 }

var _curve25519 = &curve25519_t{}

type curve25519_t struct{}

// PublicKey creates a 64-byte sequence containing 32-byte X25519 public key
// followed by a 32-byte Ed25519 public key.
func (c *curve25519_t) PublicKey(privBytes []byte) ([]byte, error) {
	ecdhPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 key: %v", err)
	}
	ecdhPub := ecdhPriv.PublicKey().Bytes()

	ed25519Priv, err := c.newEd25519PrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ed25519 key: %v", err)
	}
	ed25519Pub := ed25519Priv[32:]

	publicKey := make([]byte, 64)
	copy(publicKey, ecdhPub)
	copy(publicKey[32:], ed25519Pub)

	return publicKey, nil
}

// ECDH performs a DH exchange using X25519.
func (c *curve25519_t) ECDH(privBytes, pubBytes []byte) ([]byte, error) {
	if len(pubBytes) != 64 {
		return nil, fmt.Errorf("invalid pubkey length: must be 64")
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create X25519 key: %v", err)
	}
	pubBytes = pubBytes[:32]
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to created ECDH public key: %v", err)
	}
	secBytes, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}
	return secBytes, nil
}

// Sign signs a byte sequence using Ed25519.
func (c *curve25519_t) Sign(data []byte, privBytes []byte) ([]byte, error) {
	key, err := c.newEd25519PrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Curve25519 key: %v", err)
	}
	sigBytes := ed25519.Sign(key, data)
	return sigBytes, nil
}

// Verify checks whether a public key was used to sign some data.
func (c *curve25519_t) Verify(pubBytes, data, sigBytes []byte) bool {
	if len(pubBytes) != 64 {
		return false
	}
	pubBytes = pubBytes[32:]
	return ed25519.Verify(pubBytes, data, sigBytes)
}

func (c *curve25519_t) newEd25519PrivateKey(seed []byte) (ed25519.PrivateKey, error) {
	// this is necessary in order to wrap a potential panic
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed size is not %d", ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
