package ssh

import (
	"bytes"
	"fmt"
	"log"

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

	// encode public key
	publicKeyBase64 := encodeBase64(s.PublicKey.Marshal())

	// encode blob
	blobBase64 := encodeBase64(s.Signature.Blob)

	// create signature
	signatureBytes := append([]byte(s.Signature.Format), signatureFormatBlobSeparator)
	signatureBytes = append(signatureBytes, blobBase64...)

	// encode signature
	signatureBase64 := encodeBase64(signatureBytes)

	out := append(publicKeyBase64, publicKeySignatureSeparator)
	out = append(out, signatureBase64...)

	return out, nil
}

func parsePayload(b []byte) (ssh.PublicKey, *ssh.Signature, error) {
	dataSplt := bytes.SplitN(b, []byte{publicKeySignatureSeparator}, 2)

	if len(dataSplt) != 2 {
		return nil, nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	publicKeyBase64 := dataSplt[0]
	signatureBase64 := dataSplt[1]

	publicKeyBytes, err := decodeBase64(publicKeyBase64)
	if err != nil {
		log.Printf("decoding public key failed")
		return nil, nil, err
	}

	publicKey, err := ssh.ParsePublicKey(publicKeyBytes)
	if err != nil {
		log.Printf("parsing public key failed")
		return nil, nil, err
	}

	signature, err := parseSignature(signatureBase64)
	if err != nil {
		log.Printf("parsing signature failed")
		return nil, nil, err
	}

	return publicKey, signature, nil
}

func parseSignature(b []byte) (*ssh.Signature, error) {
	signatureBytes, err := decodeBase64(b)
	if err != nil {
		return nil, err
	}

	splt := bytes.SplitN(signatureBytes, []byte{signatureFormatBlobSeparator}, 2)

	if len(splt) != 2 {
		return nil, fmt.Errorf("cannot parse request string: invalid format")
	}

	signatureBlob, err := decodeBase64(splt[1])
	if err != nil {
		return nil, err
	}

	return &ssh.Signature{Format: string(splt[0]), Blob: signatureBlob}, nil
}
