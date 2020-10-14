package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	bastionAuthorizedKeysDir = "authorized_keys"
	bastionHostKeyFile       = "bastion_host_key"
)

func newSSH(listenAddress string, baseDir string) error {
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

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[c.User()] == nil {
				return nil, fmt.Errorf("unknown public key for %s", c.User())
			}

			if authorizedKeysMap[c.User()][string(pubKey.Marshal())] {
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
	log.Printf("Started bastion server on %s\n", listenAddress)

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Print("failed to accept incoming connection: ", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Print("failed to handshake: ", err)
			continue
		}
		log.Printf("%s logged in with key %s", conn.User(), conn.Permissions.Extensions["pubkey-fp"])

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
				log.Printf("Could not accept channel: %v", err)
				continue
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

					switch line {

					}

					fmt.Println(line)
				}
			}()
		}
	}

	return nil
}

func readSSHAuthorizedKeys(baseDir string) (map[string]map[string]bool, error) {
	authorizedKeysDir := path.Join(baseDir, bastionAuthorizedKeysDir)
	_, err := os.Stat(authorizedKeysDir)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("authorized keys directory does not exist")
	}

	authorizedKeysMap := map[string]map[string]bool{}

	files, err := filepath.Glob(path.Join(baseDir, bastionAuthorizedKeysDir, "*"))
	for _, authorizedKeyFile := range files {
		_, user := filepath.Split(authorizedKeyFile)

		// TODO: check permissions of authorized keys file
		authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ssh: failed to load authorized_keys, err: %v", err)
		}

		for len(authorizedKeysBytes) > 0 {
			pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
			if err != nil {
				log.Fatal(err)
			}

			if _, ok := authorizedKeysMap[user]; !ok {
				authorizedKeysMap[user] = map[string]bool{}
			}

			authorizedKeysMap[user][string(pubKey.Marshal())] = true
			authorizedKeysBytes = rest
		}

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
