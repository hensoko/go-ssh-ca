package main

import (
	"go-ssh-ca/ssh/server"
	"log"
	"os"
	"path"
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

	s := server.NewServer(server.Config{
		AuthorizedKeysDir: "authorized_keys",
		BaseDir:           baseDir,
		HostKeyFile:       "bastion_host_key",
	})

	// TODO: get listen address and port from flags
	err := s.ListenAndServe("127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}
}
