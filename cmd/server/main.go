package main

import (
	"context"
	"fmt"
	"go-ssh-ca/api/server"
	"log"
	"net"

	"google.golang.org/grpc"
)

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 7777))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	} // create a server instance

	log.Println("listening on 127.0.0.1:7777")

	s := grpc.NewServer()

	server.RegisterServerServer(s, NewServer())

	s.Serve(lis)
	defer s.Stop()
}

type Server struct {
	server.UnimplementedServerServer
}

func NewServer() *Server {
	return &Server{}
}

func (s Server) SignUserPublicKey(ctx context.Context, in *server.SignUserPublicKeyRequest) (*server.SignUserPublicKeyResponse, error) {
	panic("implement me")
}
