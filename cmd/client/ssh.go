package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh/knownhosts"

	"golang.org/x/crypto/ssh"
)

func newSSH(remoteAddress string) error {
	homeDir := os.Getenv("HOME")
	if len(homeDir) == 0 {
		return fmt.Errorf("HOME env not set")
	}

	sshBaseDir := path.Join(homeDir, ".ssh")

	privateKeys, err := readSSHPrivateKeys(sshBaseDir)
	if err != nil {
		return err
	}

	knownHostsCb, err := knownhosts.New(path.Join(sshBaseDir, "known_hosts"))
	if err != nil {
		return err
	}

	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.newSsh
	config := &ssh.ClientConfig{
		User: "username",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKeys...),
		},
		HostKeyCallback: knownHostsCb,
	}
	client, err := ssh.Dial("tcp", remoteAddress, config)
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

	return nil
}

func readSSHPrivateKeys(baseDir string) ([]ssh.Signer, error) {
	files, err := filepath.Glob(path.Join(baseDir, "id_rsa*"))
	if err != nil {
		return nil, err
	}

	var privateKeys []ssh.Signer
	for _, keyFile := range files {
		if strings.HasSuffix(keyFile, ".pub") {
			log.Printf("Ignoring file %s\n", keyFile)
			continue
		}

		log.Printf("Reading %s\n", keyFile)
		privateKeyBytes, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Println(err)
			continue
		}

		privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
		if err != nil {
			log.Println(err)
			continue
		}

		privateKeys = append(privateKeys, privateKey)
	}

	if len(privateKeys) == 0 {
		return nil, fmt.Errorf("ssh: no private keys found")
	}

	return privateKeys, nil
}
