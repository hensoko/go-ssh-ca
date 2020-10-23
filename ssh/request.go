package ssh

import (
	"encoding/json"

	"golang.org/x/crypto/ssh"
)

// SigningRequest contains a user and a public key and is transmitted to bastion / server to get signed
type SigningRequest struct {
	IPAddress string `json:"ip_address,omitempty"`
	Username  string `json:"username,omitempty"`

	// PublicKey in authorized keys format
	PublicKey ssh.PublicKey `json:"-"`
	// Signature verifies the integrity of the transmitted public key
	Signature *ssh.Signature `json:"signature,omitempty"`
}

func (s *SigningRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(NewWireSigningRequest(s))
}

func (s *SigningRequest) UnmarshalJSON(data []byte) error {
	var wreq WireSigningRequest
	if err := json.Unmarshal(data, &wreq); err != nil {
		return err
	}

	sr, err := wreq.SigningRequest()
	if err != nil {
		return err
	}

	*s = *sr
	return nil
}
