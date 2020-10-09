package main

import (
	"context"
	"go-ssh-ca/api"
	"log"

	"google.golang.org/grpc"
)

func main() {
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(":7777", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	bc := api.NewBastionClient(conn)

	log.Printf("Starting authentication")
	authResp, err := bc.Authenticate(context.TODO(), &api.AuthenticateRequest{
		Username: "hensoko",
		Password: "test1234",
	})
	if err != nil {
		log.Fatalf("An error occured: %s", err)
	}

	log.Printf("Authentication successful: got sessionID %q", authResp.SessionId)
}
