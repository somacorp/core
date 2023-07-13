package rnd

import (
	cryptoRand "crypto/rand"
)

// RandomBytes generates n random bytes.
func RandomBytes(n int) ([]byte, error) {
	p := make([]byte, n)
	if _, err := cryptoRand.Read(p); err != nil { // ignore n
		return nil, err
	}
	return p, nil
}
