package ssh

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	ssh2 "golang.org/x/crypto/ssh"
)

type Signer struct {
	certificateValidUntil time.Duration

	key         ssh2.Signer
	operational bool
}

func (s *Signer) HandleRequest(req *SigningRequest) (*SigningResponse, error) {
	// check if signer was setup appropriately
	if !s.operational {
		return nil, fmt.Errorf("signer: not yet operational")
	}

	// sign certificate
	log.Printf("Signing certificate for %q from %q", req.Username, req.IPAddress)
	cert, signature, err := s.sign(req.Username, s.key, req.PublicKey)
	if err != nil {
		log.Printf("SignUserPublicKey failed: signing failed: " + err.Error())
		return nil, err
	}

	out := &SigningResponse{
		ValidUntil:  time.Unix(int64(cert.ValidBefore), 0),
		Certificate: cert,
		Signature:   signature,
	}

	return out, nil
}

func (s *Signer) LoadKey(path string) error {
	// load signing private key
	key, err := ReadSSHPrivateKey(path)
	if err != nil {
		log.Printf("SignUserPublicKey failed: loading private key failed: " + err.Error())
		return err
	}

	s.key = key
	s.operational = true

	return nil
}

// sign handles actual signing and certificate generation
func (s *Signer) sign(username string, signer ssh2.Signer, publicKey ssh2.PublicKey) (*ssh2.Certificate, *ssh2.Signature, error) {
	signature, err := signer.Sign(rand.Reader, publicKey.Marshal())
	if err != nil {
		return nil, nil, fmt.Errorf("ssh2: unable to sign public key: %s", err)
	}

	// setup timestamps
	validAfter := time.Now()
	validBefore := validAfter.Add(s.certificateValidUntil)

	out := &ssh2.Certificate{
		Nonce:           nil, // TODO: find out, what Nonce does
		Key:             publicKey,
		Serial:          0, // TODO: get value from daily-reset persistet counter. persist value. format "YYYYMMDD-%d"
		CertType:        ssh2.UserCert,
		KeyId:           username + "-" + validAfter.String(),
		ValidPrincipals: []string{"test-principals"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions:     ssh2.Permissions{},
		Reserved:        nil,
		SignatureKey:    signer.PublicKey(),
		Signature:       signature,
	}

	//TODO: create signature
	return out, nil, nil
}
