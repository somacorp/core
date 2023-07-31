package enc

import (
	"strconv"

	eth "github.com/ethereum/go-ethereum/crypto"
)

func EthEncoder() *ethEncoder_t { return _ethEncoder }

var _ethEncoder = &ethEncoder_t{}

type ethEncoder_t struct{}

func (enc *ethEncoder_t) Encode(data []byte) ([]byte, error) {
	pre := enc.prefix()
	msg := string(data)
	length := strconv.Itoa(len(data))
	content := []byte(pre + length + msg)
	digest := eth.Keccak256Hash(content)
	return digest.Bytes(), nil
}

func (enc *ethEncoder_t) prefix() string {
	return "\x19Ethereum Signed Message:\n"
}
