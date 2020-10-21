package grpc

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/hensoko/go-ssh-ca/ssh"

	"github.com/hensoko/go-ssh-ca/api/server"
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
	req, err := ssh.NewRequestFromGrpcRequest(in)
	if err != nil {
		log.Printf("SignUserPublicKey failed: parsing RequestData failed: " + err.Error())
		return nil, err
	}

	// sign certificate
	log.Printf("Signing certificate for %q from %q", in.Username, in.Ip)
	res, err := s.Signer.HandleRequest(req)
	if err != nil {
		return nil, err
	}

	//TODO: create response data analog to request data

	// prepare and return response object
	out := &server.SignUserPublicKeyResponse{
		Error: &server.Error{
			Code:    0,
			Message: "success",
		},
		ResponseData: res.Bytes(),
	}

	return out, nil
}
