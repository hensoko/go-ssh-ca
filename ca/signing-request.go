package ca

import (
	"encoding/json"

	"golang.org/x/crypto/ssh"
)

// SigningRequest contains a user and a public key and is transmitted to bastion / server to get signed
type SigningRequest struct {
	// PublicKey in authorized keys format
	PublicKey ssh.PublicKey `json:"public_key"`
	// Signature verifies the integrity of the transmitted public key
	Signature ssh.Signature `json:"signature"`
}

func NewSigningRequest(publicKey ssh.PublicKey, signature ssh.Signature) *SigningRequest {
	return &SigningRequest{
		PublicKey: publicKey,
		Signature: signature,
	}
}

func (s *SigningRequest) Bytes() ([]byte, error) {
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

//func (s *SigningRequest) MarshalText() (text []byte, err error) {
//	jBytes, err := json.Marshal(s)
//	if err != nil {
//		return nil, err
//	}
//
//	base64.StdEncoding.Encode(text, jBytes)
//	return text, nil
//}
//
//func (s *SigningRequest) UnmarshalText(text []byte) (err error) {
//	var jBytes []byte
//	_, err = base64.StdEncoding.Decode(jBytes, text)
//	if err != nil {
//		return err
//	}
//
//	return json.Unmarshal(jBytes, s)
//}
