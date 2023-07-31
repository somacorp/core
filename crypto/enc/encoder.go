package enc

type Encoder interface {
	Encode(data []byte) ([]byte, error)
}

var _ Encoder = (*ethEncoder_t)(nil)
var _ Encoder = (*sha256Encoder_t)(nil)
var _ Encoder = (*trivialEncoder_t)(nil)
