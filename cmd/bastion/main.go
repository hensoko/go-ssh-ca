package main

import (
	"log"
	"os"
	"path"

	"github.com/hensoko/go-ssh-ca/ssh"
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

	// TODO: merge ssh.server package with ssh package
	s := ssh.NewServer(ssh.ServerConfig{
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
