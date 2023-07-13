package enc

func TrivialEncoder() *trivialEncoder_t { return _trivialEncoder }

var _trivialEncoder = &trivialEncoder_t{}

type trivialEncoder_t struct{}

func (enc *trivialEncoder_t) Encode(data []byte) ([]byte, error) {
	return data, nil
}
