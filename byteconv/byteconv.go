package byteconv

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

func ToHex(b []byte) string {
	return hex.EncodeToString(b)
}

func FromHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func ToB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func FromB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func ToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func FromBigInt(x *big.Int) []byte {
	return x.Bytes()
}
