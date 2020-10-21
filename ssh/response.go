package ssh

import (
	"time"

	"golang.org/x/crypto/ssh"
)

type SigningResponse struct {
	//TODO add more metadata
	ValidUntil time.Time

	Certificate *ssh.Certificate
	Signature   *ssh.Signature
}

func NewFromGrpcResponse() (*SigningResponse, error) {
	return nil, nil
}

func (s *SigningResponse) Bytes() []byte {
	return nil
}
