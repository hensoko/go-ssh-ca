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
		log.Fatalf("HOME env not set")
	}

	// TODO: merge ssh.client package with ssh package
	c := ssh.NewClient(ssh.ClientConfig{
		BaseDir: path.Join(homeDir, ".ssh"),
	})

	// TODO: read username from flag
	err := c.Dial("hensoko", "127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}

	os.Exit(0)
}
