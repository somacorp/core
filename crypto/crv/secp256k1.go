package crv

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eth "github.com/ethereum/go-ethereum/crypto"
)

func Secp256k1() *secp256k1_t { return _secp256k1 }

var _secp256k1 = &secp256k1_t{}

type secp256k1_t struct{}

// PublicKey creates a secp256k1 public key from a private key.
func (c *secp256k1_t) PublicKey(privBytes []byte) ([]byte, error) {
	priv, err := eth.ToECDSA(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA-secp256k1 key: %v", err)
	}
	pubBytes := eth.FromECDSAPub(&priv.PublicKey)
	return pubBytes, nil
}

// ECDH performs a DH exchange using the secp256k1 curve.
func (c *secp256k1_t) ECDH(privBytes, pubBytes []byte) ([]byte, error) {
	privSecp256k1 := secp256k1.PrivKeyFromBytes(privBytes)
	pubSecp256k1, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create public secp256k1 key: %v", err)
	}
	secBytes := secp256k1.GenerateSharedSecret(privSecp256k1, pubSecp256k1)
	return secBytes, nil
}

// Sign signs a 32-byte sequence using ECDSA with the secp256k1 curve.
func (c *secp256k1_t) Sign(digest []byte, privBytes []byte) ([]byte, error) {
	priv, err := eth.ToECDSA(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA-secp256k1 key: %v", err)
	}
	sigBytes, err := eth.Sign(digest, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %v", err)
	}
	return sigBytes, nil
}

// Verify checks whether a public key was used to sign some data.
// It is assumed that the signature contains a recover ID, i.e. it is the
// exact output of this curve's Sign function.
func (c *secp256k1_t) Verify(pubBytes, data, sigBytes []byte) bool {
	sigBytesNoRecoverID := sigBytes[:len(sigBytes)-1]
	return eth.VerifySignature(pubBytes, data, sigBytesNoRecoverID)
}
