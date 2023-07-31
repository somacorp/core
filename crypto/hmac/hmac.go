package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func Create(key, message []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(message); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func Verify(signature, message, key []byte) error {
	h, err := Create(key, message)
	if err != nil {
		return err
	}
	if !bytes.Equal(signature, h) {
		return fmt.Errorf("bytes are not equal")
	}
	return nil
}
