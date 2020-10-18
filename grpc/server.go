package grpc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"path"
	"time"

	"github.com/hensoko/go-ssh-ca/ca"

	"github.com/hensoko/go-ssh-ca/api/server"
	"github.com/hensoko/go-ssh-ca/ssh"
	baseSSH "golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type ServerConfig struct {
	BaseDir                     string
	CertificateValidityDuration time.Duration
	HostKeyFileName             string
}

type Server struct {
	server.UnimplementedServerServer

	c *ServerConfig
}

func NewServer(config *ServerConfig) *Server {
	return &Server{
		c: config,
	}
}

func (s *Server) ListenAndServe(listenAddress string) error {
	// create listening socket
	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Printf("listening on %s", listenAddress)

	// create grpc server instance and register Server instance as grpc handler
	grpcServer := grpc.NewServer()
	server.RegisterServerServer(grpcServer, s)
	err = grpcServer.Serve(lis)
	defer grpcServer.Stop()

	return err
}

// SignUserPublicKey is part of the grpc server interface
func (s *Server) SignUserPublicKey(ctx context.Context, in *server.SignUserPublicKeyRequest) (*server.SignUserPublicKeyResponse, error) {
	// load signing private key
	key, err := ssh.ReadSSHPrivateKey(path.Join(s.c.BaseDir, s.c.HostKeyFileName))
	if err != nil {
		log.Printf("SignUserPublicKey failed: loading private key failed: " + err.Error())
		return nil, err
	}

	// parse request data

	fmt.Println(in.RequestData)

	req, err := ca.NewSigningRequestFromString(in.RequestData)
	if err != nil {
		log.Printf("SignUserPublicKey failed: parsing RequestData failed: " + err.Error())
		return nil, err
	}

	//sign certificate
	log.Printf("Signing certificate for %q from %q", in.Username, in.Ip)
	cert, err := s.signCertificate(in.Username, key, req.PublicKey)
	if err != nil {
		log.Printf("SignUserPublicKey failed: signing failed: " + err.Error())
		return nil, err
	}

	cert.Marshal()

	out := &server.SignUserPublicKeyResponse{
		Error: &server.Error{
			Code:    0,
			Message: "success",
		},
		Certificate: base64.StdEncoding.EncodeToString(cert.Marshal()),
	}

	return out, nil
}

func (s *Server) signCertificate(username string, signer baseSSH.Signer, publicKey baseSSH.PublicKey) (*baseSSH.Certificate, error) {
	signature, err := signer.Sign(rand.Reader, publicKey.Marshal())
	if err != nil {
		return nil, fmt.Errorf("ssh: unable to sign public key: %s", err)
	}

	validAfter := time.Now()
	validBefore := validAfter.Add(s.c.CertificateValidityDuration)

	out := &baseSSH.Certificate{
		Nonce:           nil,
		Key:             publicKey,
		Serial:          0,
		CertType:        baseSSH.UserCert,
		KeyId:           username + "-" + validAfter.String(),
		ValidPrincipals: []string{"test-principals"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions:     baseSSH.Permissions{},
		Reserved:        nil,
		SignatureKey:    signer.PublicKey(),
		Signature:       signature,
	}

	return out, nil
}
