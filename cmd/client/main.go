package main

import (
	"go-ssh-ca/ssh/client"
	"log"
	"os"
	"path"
)

func main() {
	homeDir := os.Getenv("HOME")
	if len(homeDir) == 0 {
		log.Fatalf("HOME env not set")
	}

	c := client.NewClient(client.Config{
		BaseDir: path.Join(homeDir, ".ssh"),
	})

	// TODO: read username from flag
	err := c.Dial("hensoko", "127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}
}
