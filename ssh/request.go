package ssh

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/hensoko/go-ssh-ca/api/server"

	"golang.org/x/crypto/ssh"
)

const (
	publicKeySignatureSeparator  byte = '.'
	signatureFormatBlobSeparator byte = ':'
)

// SigningRequest contains a user and a public key and is transmitted to bastion / server to get signed
type SigningRequest struct {
	IPAddress string
	Username  string

	// PublicKey in authorized keys format
	PublicKey ssh.PublicKey
	// Signature verifies the integrity of the transmitted public key
	Signature *ssh.Signature
}

// NewRequestFromClientRequest creates a new SigningRequest and sets public key and signature
func NewRequestFromClientRequest(ipAddress string, username string, payload []byte) (*SigningRequest, error) {
	out := &SigningRequest{
		IPAddress: ipAddress,
		Username:  username,
	}

	publicKey, signature, err := parsePayload(payload)
	if err != nil {
		return nil, err
	}

	out.PublicKey = publicKey
	out.Signature = signature

	return out, err
}

// NewRequestFromGrpcRequest parses a bytes array and returns a SigningRequest
func NewRequestFromGrpcRequest(req *server.SignUserPublicKeyRequest) (*SigningRequest, error) {
	out := &SigningRequest{
		IPAddress: req.Ip,
		Username:  req.Username,
	}

	publicKey, signature, err := parsePayload(req.RequestData)
	if err != nil {
		return nil, err
	}

	out.PublicKey = publicKey
	out.Signature = signature

	return out, err
}

func (s *SigningRequest) PayloadBytes() ([]byte, error) {
	if s.PublicKey == nil || s.Signature == nil {
		return nil, fmt.Errorf("PublicKey or Signature not set")
	}

	keyBytes := s.PublicKey.Marshal()
	publicKey := make([]byte, base64.StdEncoding.EncodedLen(len(keyBytes)))
	base64.StdEncoding.Encode(publicKey, keyBytes)

	format := []byte(s.Signature.Format)
	blob := make([]byte, base64.StdEncoding.EncodedLen(len(s.Signature.Blob)))
	base64.StdEncoding.Encode(blob, s.Signature.Blob)

	signatureBytes := append(format, signatureFormatBlobSeparator)
	signatureBytes = append(signatureBytes, blob...)

	out := append(keyBytes, publicKeySignatureSeparator)
	out = append(out, signatureBytes...)

	return out, nil
}

func parsePayload(b []byte) (ssh.PublicKey, *ssh.Signature, error) {
	dataSplt := bytes.Split(b, []byte{publicKeySignatureSeparator})
	if len(dataSplt) != 2 {
		return nil, nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	publicKeyBytes := make([]byte, base64.StdEncoding.DecodedLen(len(dataSplt[0])))
	_, err := base64.StdEncoding.Decode(publicKeyBytes, dataSplt[0])
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	signature, err := parseSignature(dataSplt[1])
	if err != nil {
		return nil, nil, err
	}

	return publicKey, signature, nil
}

func parseSignature(b []byte) (*ssh.Signature, error) {
	signatureBytes := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	_, err := base64.StdEncoding.Decode(signatureBytes, b)
	if err != nil {
		return nil, err
	}

	splt := bytes.Split(signatureBytes, []byte{signatureFormatBlobSeparator})
	if len(splt) != 2 {
		return nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	signatureBlob := make([]byte, base64.StdEncoding.DecodedLen(len(splt[1])))
	_, err = base64.StdEncoding.Decode(signatureBytes, splt[1])
	if err != nil {
		return nil, err
	}

	return &ssh.Signature{Format: string(splt[0]), Blob: signatureBlob}, nil
}
