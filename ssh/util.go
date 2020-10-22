package ssh

import (
	"bytes"
	"encoding/base64"
)

func encodeBase64(b []byte) []byte {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(enc, b)

	return enc
}

func decodeBase64(b []byte) ([]byte, error) {
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	_, err := base64.StdEncoding.Decode(dec, b)
	if err != nil {
		return nil, err
	}

	// trim \x00
	dec = bytes.TrimRight(dec, "\x00")

	return dec, nil
}
