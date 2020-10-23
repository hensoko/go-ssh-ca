package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	ssh2 "golang.org/x/crypto/ssh"

	"github.com/hensoko/go-ssh-ca/api/server"
	"github.com/hensoko/go-ssh-ca/ssh"
	"google.golang.org/grpc"
)

// A ServerConfig object stores customizable options that affect server operation
type ServerConfig struct {
	BaseDir                     string
	CertificateValidityDuration time.Duration
	HostKeyFileName             string
}

// Server implements server.ServerServer and handles grpc requests
type Server struct {
	server.UnimplementedServerServer

	Signer ssh.Signer
}

// ListenAndServe sets up a tcp socket listening on given <host>:<port> listenAddress
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

// SignUserPublicKey is part of the grpc server interface and processes incoming server.SignUserPublicKeyRequest objects
// TODO: instead of returning error create response object containing server.Error
func (s *Server) SignUserPublicKey(ctx context.Context, in *server.SignUserPublicKeyRequest) (*server.SignUserPublicKeyResponse, error) {
	// parse request
	req := &ssh.SigningRequest{}
	err := json.Unmarshal(in.RequestData, req)
	if err != nil {
		log.Printf("Failed to unmarshal request data")
		return nil, err
	}

	log.Printf("Incoming signing request from %s (%s)", req.Username, req.IPAddress)

	signature := &ssh2.Signature{}
	err = json.Unmarshal(in.Signature, signature)
	if err != nil {
		return nil, err
	}

	log.Printf("%+v", req)

	// verify signature
	// TODO SECURITY: ensure public key belongs to bastion
	err = req.PublicKey.Verify(in.RequestData, signature)
	if err != nil {
		log.Printf("ssh: invalid request: signature invalid")
		return nil, fmt.Errorf("ssh: invalid request: invalid signature")
	}

	// sign certificate
	log.Printf("Signing certificate for %q from %q", req.Username, req.IPAddress)
	res, err := s.Signer.HandleRequest(req)
	if err != nil {
		return nil, err
	}

	// marshal response
	resJson, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}

	// prepare and return response object
	out := &server.SignUserPublicKeyResponse{
		Error: &server.Error{
			Code:    0,
			Message: "success",
		},
		ResponseData: resJson,
	}

	return out, nil
}
