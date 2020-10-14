package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	bastionAuthorizedKeysFile = "bastion_authorized_keys"
	bastionHostKeyFile        = "bastion_host_key"
)

func newSSH(baseDir string) error {
	authorizedKeysMap, err := readSSHAuthorizedKeys(baseDir)
	if err != nil {
		return err
	}

	hostKey, err := readSSHHostKey(baseDir)
	if err != nil {
		return err
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			log.Printf("New connection from %s using method %s", conn.LocalAddr().String(), method)
		},

		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password authentication is not supported")
		},

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	config.AddHostKey(hostKey)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				req.Reply(req.Type == "shell", nil)
			}
		}(requests)

		term := terminal.NewTerminal(channel, "> ")

		go func() {
			defer channel.Close()
			for {
				line, err := term.ReadLine()
				if err != nil {
					break
				}
				fmt.Println(line)
			}
		}()
	}

	return nil
}

func readSSHAuthorizedKeys(baseDir string) (map[string]bool, error) {
	authorizedKeysFile := path.Join(baseDir, bastionAuthorizedKeysFile)

	_, err := os.Stat(authorizedKeysFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("ssh: authorized keys file not found")
	} else if err != nil {
		return nil, err
	}

	// TODO: check permissions of authorized keys file

	authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeysFile)
	if err != nil {
		return nil, fmt.Errorf("ssh: failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	if len(authorizedKeysMap) == 0 {
		return nil, fmt.Errorf("ssh: no authorized keys defined")
	}

	return authorizedKeysMap, nil
}

func readSSHHostKey(baseDir string) (ssh.Signer, error) {
	hostKeyFile := path.Join(baseDir, bastionHostKeyFile)
	_, err := os.Stat(hostKeyFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("ssh: host key file not found")
	} else if err != nil {
		return nil, err
	}

	hostKeyBytes, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		log.Fatal("Failed to load hostKey key: ", err)
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse hostKey key: ", err)
	}

	return hostKey, nil
}
