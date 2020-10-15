package ca

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	PublicKeySignatureSeparator  = "."
	SignatureFormatBlobSeparator = ":"
)

// SigningRequest contains a user and a public key and is transmitted to bastion / server to get signed
type SigningRequest struct {
	// PublicKey in authorized keys format
	PublicKey ssh.PublicKey
	// Signature verifies the integrity of the transmitted public key
	Signature ssh.Signature
}

func NewSigningRequest(publicKey ssh.PublicKey, signature ssh.Signature) *SigningRequest {
	return &SigningRequest{
		PublicKey: publicKey,
		Signature: signature,
	}
}

func NewSigningRequestFromString(s string) (out *SigningRequest, err error) {
	out = &SigningRequest{}

	dataSplt := strings.Split(s, PublicKeySignatureSeparator)
	if len(dataSplt) != 2 {
		log.Print("splitted data no 2")
		return nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	publicKeyHex := dataSplt[0]
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyHex)
	if err != nil {
		return nil, err
	}

	out.PublicKey, err = ssh.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	signatureHex := dataSplt[1]
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureHex)
	if err != nil {
		return nil, err
	}

	signatureStringSplt := strings.Split(string(signatureBytes), SignatureFormatBlobSeparator)
	if len(signatureStringSplt) != 2 {
		return nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	signatureBlob, err := base64.StdEncoding.DecodeString(signatureStringSplt[1])
	if err != nil {
		return nil, err
	}

	out.Signature = ssh.Signature{
		Format: signatureStringSplt[0],
		Blob:   signatureBlob,
	}

	return out, err
}

func (s *SigningRequest) String() (out string, err error) {
	publicKeyBytes := s.PublicKey.Marshal()
	publicKeyHex := base64.StdEncoding.EncodeToString(publicKeyBytes)

	signatureString := fmt.Sprintf("%s%s%s", s.Signature.Format, SignatureFormatBlobSeparator, base64.StdEncoding.EncodeToString(s.Signature.Blob))
	signatureHex := base64.StdEncoding.EncodeToString([]byte(signatureString))

	out = publicKeyHex + PublicKeySignatureSeparator + signatureHex

	return out, nil
}
