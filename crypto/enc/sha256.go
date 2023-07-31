package enc

import (
	"crypto/sha256"
)

func SHA256Encoder() *sha256Encoder_t { return _sha256Encoder }

var _sha256Encoder = &sha256Encoder_t{}

type sha256Encoder_t struct{}

func (enc *sha256Encoder_t) Encode(data []byte) ([]byte, error) {
	return createSHA256(data), nil
}

func createSHA256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum((nil))
}
