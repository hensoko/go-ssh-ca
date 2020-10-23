package ssh

import (
	"golang.org/x/crypto/ssh"
)

type SigningRequestAlias SigningRequest
type WireSigningRequest struct {
	SigningRequestAlias

	PublicKey []byte `json:"public_key,omitempty"`
}

func NewWireSigningRequest(req *SigningRequest) *WireSigningRequest {
	return &WireSigningRequest{
		SigningRequestAlias(*req),
		req.PublicKey.Marshal(),
	}
}

func (w *WireSigningRequest) SigningRequest() (*SigningRequest, error) {
	pubKey, err := ssh.ParsePublicKey(w.PublicKey)
	if err != nil {
		return nil, err
	}

	req := SigningRequest(w.SigningRequestAlias)
	req.PublicKey = pubKey

	return &req, nil
}
