package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type Server struct {
	c Config
}

func NewServer(c Config) *Server {
	return &Server{
		c: c,
	}
}

func (s *Server) ListenAndServe(listenAddress string) error {
	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	log.Printf("started bastion server on %s\n", listenAddress)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Print("failed to accept incoming connection: ", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming
		// net.Conn.

		config, err := s.configure()
		if err != nil {
			log.Fatal("ssh: invalid config")
		}
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Print("failed to handshake: ", err)
			continue
		}
		log.Printf("%s logged in with key %s", conn.User(), conn.Permissions.Extensions["pubkey-fp"])

		// The incoming Request channel must be serviced.
		go ssh.DiscardRequests(reqs)
		go s.handleChannels(chans)
	}

	return nil
}

func (s *Server) configure() (*ssh.ServerConfig, error) {
	authorizedKeysMap, err := s.readSSHAuthorizedKeys()
	if err != nil {
		return nil, err
	}

	hostKey, err := s.readSSHHostKey()
	if err != nil {
		return nil, err
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
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

	return config, nil
}

func (s *Server) handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		go s.handleChannel(newChannel)
	}
}

func (s *Server) handleChannel(newChannel ssh.NewChannel) {
	log.Printf("New Channel of type %s", newChannel.ChannelType())

	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
	}

	// accept session channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %v", err)
		return
	}

	go func(in <-chan *ssh.Request) {
		for req := range in {
			log.Printf("Got out-of-band request of type %s", req.Type)
			// only handle shell requests
			switch req.Type {
			case "exec", "shell":
				req.Reply(true, nil)

			default:
				req.Reply(false, nil)
			}
		}
	}(requests)

	term := terminal.NewTerminal(channel, "")

	go func() {
		defer channel.Close()

		for {
			log.Print("Reading line...")
			line, err := term.ReadLine()
			if err != nil {
				break
			}

			lineSplitted := strings.SplitN(line, " ", 1)

			if len(lineSplitted) != 2 {
				log.Printf("Invalied request length")
			}

			cmd := lineSplitted[0]
			payload := lineSplitted[1]

			switch cmd {

			case "sign-public-key":
				log.Printf("Got sign-public-key request with payload: %s", payload)
				term.Write([]byte("blablabla"))

			default:
				log.Printf("Invalid command %s", line)
			}
		}
	}()
}

func (s *Server) readSSHAuthorizedKeys() (map[string]map[string]bool, error) {
	authorizedKeysDir := path.Join(s.c.BaseDir, s.c.AuthorizedKeysDir)
	_, err := os.Stat(authorizedKeysDir)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("authorized keys directory does not exist")
	}

	authorizedKeysMap := map[string]map[string]bool{}

	files, err := filepath.Glob(path.Join(s.c.BaseDir, s.c.AuthorizedKeysDir, "*"))
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

func (s *Server) readSSHHostKey() (ssh.Signer, error) {
	hostKeyFile := path.Join(s.c.BaseDir, s.c.HostKeyFile)
	_, err := os.Stat(hostKeyFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("ssh: host key file not found")
	}

	if err != nil {
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
