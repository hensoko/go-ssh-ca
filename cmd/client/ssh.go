package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func newSSH(username string, remoteAddress string) error {
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
		User: username,
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

	log.Printf("Connected to %s\n", remoteAddress)

	// generate session key after connection is established
	log.Printf("Generating Session Key... ")
	sessionKeyPath, err := generateSessionKey(sshBaseDir)
	if err != nil {
		log.Println("Failed")
		return err
	}
	log.Println("Successful")

	log.Printf("Reading Session Key... ")
	sessionKey, err := readSessionKey(sessionKeyPath)
	if err != nil {
		log.Println("Failed")
		return err
	}
	log.Println("Successful")

	sessionPublicKeyBytes := sessionKey.PublicKey().Marshal()

	channel, reqs, err := client.OpenChannel("sign-public-channel", sessionPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("ssh: cannot open channel: %s", err)
	}

	go func() {
		for req := range reqs {
			// default, preserving OpenSSH behaviour
			req.Reply(false, nil)
		}
	}()

	l, err := channel.Write([]byte("bla"))
	if err != nil {
		return err
	}

	log.Println(l)

	//// Each ClientConn can support multiple interactive sessions,
	//// represented by a Session.
	//session, err := client.NewSession()
	//if err != nil {
	//	log.Fatal("Failed to create session: ", err)
	//}
	//defer session.Close()
	//
	//// Once a Session is created, you can execute a single command on
	//// the remote side using the Run method.
	//var b bytes.Buffer
	//session.Stdout = &b
	//if err := session.Run("/usr/bin/whoami"); err != nil {
	//	log.Fatal("Failed to run: " + err.Error())
	//}
	//fmt.Println(b.String())

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

func generateSessionKey(baseDir string) (sessionKeyFilename string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}

	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// create temporary file and close it as we use ioutil package to write content to it
	f, err := ioutil.TempFile(baseDir, "ssh-session-key")
	if err != nil {
		return "", err
	}

	sessionKeyFilename = f.Name()
	publicKeyFilename := sessionKeyFilename + ".pub"
	f.Close()

	err = ioutil.WriteFile(sessionKeyFilename, pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		return "", err
	}

	// create ssh public key from private key
	publicRsaKey, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		return "", err
	}

	// marshal to authorized keys format
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	err = ioutil.WriteFile(publicKeyFilename, pubKeyBytes, 0644)
	if err != nil {
		return "", err
	}

	return sessionKeyFilename, nil
}

func readSessionKey(sessionKeyPath string) (ssh.Signer, error) {
	_, err := os.Stat(sessionKeyPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("session key file %q does not exist", sessionKeyPath)
	}

	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := ioutil.ReadFile(sessionKeyPath)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(privateKeyBytes)
}
