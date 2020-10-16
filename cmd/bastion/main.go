package main

import (
	"context"
	"fmt"
	signerServer "go-ssh-ca/api/server"
	"go-ssh-ca/ssh/server"
	"log"
	"os"
	"path"

	"google.golang.org/grpc"
)

func main() {
	homeDir := os.Getenv("HOME")
	if len(homeDir) == 0 {
		log.Fatalf("ssh: cannot find homedir")
	}

	// TODO: use path from flag
	baseDir := path.Join(homeDir, "projects", "priv", "go-ssh-ca", "_bastion")
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		log.Fatalf("base directory %q does not exist", baseDir)
	}

	err := initGrpc()
	if err != nil {
		log.Fatalf(err.Error())
	}

	// TODO: merge ssh.server package with ssh package
	s := server.NewServer(server.Config{
		AuthorizedKeysDir: "authorized_keys",
		BaseDir:           baseDir,
		HostKeyFile:       "bastion_host_key",
	})

	// TODO: get listen address and port from flags
	err = s.ListenAndServe("127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}
}

func initGrpc() error {
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithInsecure())
	conn, err := grpc.Dial("127.0.0.1:7777", dialOpts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	signerClient := signerServer.NewServerClient(conn)

	var callOpts []grpc.CallOption
	resp, err := signerClient.SignUserPublicKey(
		context.Background(),
		&signerServer.SignUserPublicKeyRequest{
			Ip:          "127.0.0.1",
			Username:    "hensoko",
			RequestData: "test.123",
		},
		callOpts...,
	)
	if err != nil {
		return err
	}

	fmt.Printf("%+v", resp)
	return nil
}
