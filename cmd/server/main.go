package main

import (
	"log"
	"os"
	"path"

	"github.com/hensoko/go-ssh-ca/ssh"

	"github.com/hensoko/go-ssh-ca/grpc"
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

	// TODO: get listen address and port from flags
	// load signing key
	sign := ssh.Signer{}
	err := sign.LoadKey(path.Join(os.Getenv("HOME"), "projects/priv/go-ssh-ca/_server", "id_rsa-ca"))
	if err != nil {
		log.Fatalf(err.Error())
	}

	s := &grpc.Server{Signer: sign}
	err = s.ListenAndServe("127.0.0.1:7777")
	if err != nil {
		log.Fatalf(err.Error())
	}
}
