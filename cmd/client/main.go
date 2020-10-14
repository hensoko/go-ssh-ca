package main

import (
	"bytes"
	"context"
	"fmt"
	"go-ssh-ca/bastion/api"
	"log"

	"golang.org/x/crypto/ssh"

	"google.golang.org/grpc"
)

func main() {
	newSSH()
}

func newGrpc() {
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

func newSSH() {
	var hostKey ssh.PublicKey
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.newSsh
	config := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.Password("yourpassword"),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
	client, err := ssh.Dial("tcp", "yourserver.com:22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	fmt.Println(b.String())
}
