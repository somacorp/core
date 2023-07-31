package signer

import (
	"github.com/somacorp/core/crypto/crv"
	"github.com/somacorp/core/crypto/enc"
)

type Signer struct {
	privateKey []byte
	PublicKey  []byte
	Curve      crv.Curve
	Encoder    enc.Encoder
}

func New(privateKey []byte, curve crv.Curve, encoder enc.Encoder) (*Signer, error) {
	publicKey, err := curve.PublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{
		privateKey: privateKey,
		PublicKey:  publicKey,
		Curve:      curve,
		Encoder:    encoder,
	}, nil
}

func (s *Signer) PrivateKey() []byte {
	return s.privateKey
}

func (s *Signer) ECDH(publicKey []byte) ([]byte, error) {
	return s.Curve.ECDH(s.privateKey, publicKey)
}

func (s *Signer) Sign(message string) ([]byte, error) {
	digest, err := s.Encoder.Encode([]byte(message))
	if err != nil {
		return nil, err
	}

	signature, err := s.Curve.Sign(digest, s.privateKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (s *Signer) Verify(pubBytes []byte, data []byte, sigBytes []byte) bool {
	return s.Curve.Verify(pubBytes, data, sigBytes)
}
