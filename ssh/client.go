package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hensoko/go-ssh-ca/ca"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type ClientConfig struct {
	BaseDir string
}

const (
	ClientDefaultSessionKeyBits = 2048
)

type Client struct {
	c ClientConfig
}

func NewClient(c ClientConfig) *Client {
	return &Client{
		c: c,
	}
}

func (c *Client) Dial(username string, remoteAddress string) error {
	clientConfig, err := c.configure(username)
	if err != nil {
		return err
	}

	client, err := ssh.Dial("tcp", remoteAddress, clientConfig)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	log.Printf("Connected to %s\n", remoteAddress)

	// generate session key after connection is established
	log.Printf("Generating Session Key... ")
	privateKey, err := rsa.GenerateKey(rand.Reader, ClientDefaultSessionKeyBits)

	// create temporary file and close it as we use ioutil package to write content to it
	f, err := ioutil.TempFile(c.c.BaseDir, fmt.Sprintf("ssh-session-key_%d_", time.Now().Unix()))
	if err != nil {
		return err
	}

	privateKeyFileName := path.Base(f.Name())
	publicKeyFileName := privateKeyFileName + ".pub"
	f.Close()

	// store session key on disk
	err = c.storeKeyPair(privateKey, c.c.BaseDir, privateKeyFileName, publicKeyFileName)
	if err != nil {
		return err
	}

	// TODO: delete session key files after usage

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}
	log.Println("Successful")

	s, err := client.NewSession() // Create new SSH session
	if err != nil {
		return err
	}

	pubKey := signer.PublicKey()
	pubKeySignature, err := signer.Sign(rand.Reader, pubKey.Marshal())
	if err != nil {
		return fmt.Errorf("ssh: unable to sign public key: %s", err)
	}

	log.Printf("Creating signing request")
	signingRequestString, err := ca.NewSigningRequest(signer.PublicKey(), *pubKeySignature).String()
	if err != nil {
		return err
	}

	log.Printf("Sending signing request")
	cmd := "sign-public-key " + signingRequestString

	stdout, err := s.StdoutPipe()
	if err != nil {
		log.Fatalf(err.Error())
	}

	buf := &strings.Builder{}
	go io.Copy(buf, stdout)

	err = s.Run(cmd)
	if err != nil && err != io.EOF {
		log.Fatalf(err.Error())
	}

	log.Printf("Connection closed")

	log.Println(buf.String())

	return nil
}

func (c *Client) configure(username string) (*ssh.ClientConfig, error) {
	privateKeys, err := c.readSSHPrivateKeys()
	if err != nil {
		return nil, err
	}

	knownHostsCb, err := knownhosts.New(path.Join(c.c.BaseDir, "known_hosts"))
	if err != nil {
		return nil, err
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

	return config, nil
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
		privateKey, err := ReadSSHPrivateKey(keyFile)
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

func (c *Client) storeKeyPair(key *rsa.PrivateKey, baseDir string, privateKeyFileName string, publicKeyFileName string) error {
	err := ioutil.WriteFile(
		path.Join(baseDir, privateKeyFileName),
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			},
		),
		0600, // private key must only be read by owner
	)
	if err != nil {
		return err
	}

	// create ssh public key from private key
	publicRsaKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return err
	}

	// marshal to authorized keys format
	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return ioutil.WriteFile(
		path.Join(baseDir, publicKeyFileName),
		pubKeyBytes,
		0644,
	)
}
