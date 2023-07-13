// package crv provides wrappers around a number of elliptic curves used in the
// creation of public keys, creation of signatures, creation of ECDH secrets
// and verification of signatures.
package crv

type Curve interface {
	PublicKey(privBytes []byte) ([]byte, error)
	ECDH(privBytes, pubBytes []byte) ([]byte, error)
	Sign(data, privBytes []byte) ([]byte, error)
	Verify(pubBytes, data, sigBytes []byte) bool
}

var _ Curve = (*curve25519_t)(nil)
var _ Curve = (*secp256k1_t)(nil)
