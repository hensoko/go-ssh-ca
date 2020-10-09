package main

import (
	"fmt"
	"go-ssh-ca/api"
	"go-ssh-ca/bastion"
	"log"
	"net"
	"os"

	"github.com/rs/zerolog"

	"google.golang.org/grpc"
)

func main() {
	// create a listener on TCP port 7777
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 7777))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	} // create a server instance

	log.Println("listening on 127.0.0.1:7777")

	s := grpc.NewServer()
	l := zerolog.New(os.Stderr)
	b := bastion.NewBastion(&l)

	api.RegisterBastionServer(s, b)

	s.Serve(lis)
	defer s.Stop()
}
