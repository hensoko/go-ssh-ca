package grpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"path"

	"github.com/hensoko/go-ssh-ca/ssh"

	"github.com/hensoko/go-ssh-ca/api/server"
	"google.golang.org/grpc"
)

type ServerConfig struct {
	BaseDir         string
	HostKeyFileName string
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
	// load server host key
	hostKey, err := ssh.ReadSSHHostKey(path.Join(s.c.BaseDir, s.c.HostKeyFileName))
	if err != nil {
		return err
	}

	fmt.Println(hostKey)

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

	panic("implement me")
}
