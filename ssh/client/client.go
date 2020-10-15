package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go-ssh-ca/ca"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	SessionKeyBits = 2048
)

type Client struct {
	c Config
}

func NewClient(c Config) *Client {
	return &Client{
		c: c,
	}
}

func (c *Client) Dial(username string, remoteAddress string) error {
	privateKeys, err := c.readSSHPrivateKeys()
	if err != nil {
		return err
	}

	knownHostsCb, err := knownhosts.New(path.Join(c.c.BaseDir, "known_hosts"))
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
	sessionKeyPath, err := c.generateSessionKey()
	defer os.Remove(sessionKeyPath)
	defer os.Remove(sessionKeyPath + ".pub")

	if err != nil {
		log.Println("Failed")
		return err
	}
	log.Println("Successful")

	log.Printf("Reading Session Key... ")
	sessionKey, err := c.readSessionKey(sessionKeyPath)
	if err != nil {
		log.Println("Failed")
		return err
	}
	log.Println("Successful")

	s, err := client.NewSession() // Create new SSH session
	if err != nil {
		return err
	}

	stdout := bytes.Buffer{}
	s.Stdout = &stdout   // Write Session Stdout to buffer
	s.Stderr = os.Stderr // Route session Stderr to system Stderr

	pubKey := sessionKey.PublicKey()
	pubKeySignature, err := sessionKey.Sign(rand.Reader, pubKey.Marshal())
	if err != nil {
		return fmt.Errorf("ssh: unable to sign public key: %s", err)
	}

	log.Printf("Creating signing request")
	requestBytes, err := ca.NewSigningRequest(sessionKey.PublicKey(), *pubKeySignature).Bytes()
	if err != nil {
		return err
	}

	log.Printf("Sending signing request")
	cmd := "sign-public-key " + string(requestBytes)
	err = s.Run(cmd + "\n")
	if err != nil {
		return err
	}

	err = s.Wait()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) readSSHPrivateKeys() ([]ssh.Signer, error) {
	files, err := filepath.Glob(path.Join(c.c.BaseDir, "id_rsa*"))
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

func (c *Client) generateSessionKey() (sessionKeyFilename string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, SessionKeyBits)
	if err != nil {
		return "", err
	}

	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// create temporary file and close it as we use ioutil package to write content to it
	f, err := ioutil.TempFile(c.c.BaseDir, fmt.Sprintf("ssh-session-key_%d_", time.Now().Unix()))
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

func (c *Client) readSessionKey(sessionKeyPath string) (ssh.Signer, error) {
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
