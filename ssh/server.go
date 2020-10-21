package ssh

import (
	"context"
	"fmt"
	"log"
	"net"
	"path"
	"strings"

	"github.com/hensoko/go-ssh-ca/api/server"
	"google.golang.org/grpc"

	"golang.org/x/crypto/ssh"
)

type ServerConfig struct {
	AuthorizedKeysDir string
	BaseDir           string
	HostKeyFile       string
}

type Server struct {
	c ServerConfig
}

func NewServer(c ServerConfig) *Server {
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

	log.Printf("started ssh server on %s\n", listenAddress)

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
	authorizedKeysMap, err := ReadSSHAuthorizedKeys(path.Join(s.c.BaseDir, s.c.AuthorizedKeysDir))
	if err != nil {
		return nil, err
	}

	hostKey, err := ReadSSHPrivateKey(path.Join(s.c.BaseDir, s.c.HostKeyFile))
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
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
	}

	// accept session channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel: %v", err)
		return
	}

	go func(reqs <-chan *ssh.Request) {
		for req := range reqs {
			if req.Type != "exec" { // only handle exec requests
				req.Reply(false, nil)
				continue
			}

			log.Print("Handline exec request")
			s.handleExec(channel, req)
		}
	}(requests)
}

func (s *Server) handleExec(channel ssh.Channel, req *ssh.Request) {
	if len(req.Payload) == 0 {
		log.Print("ssh: invalid request: empty payload")
		closeWrite("ssh: invalid request: empty payload", channel)
		return
	}

	// sanitize payload
	pl := string(req.Payload[4:])
	pl = strings.TrimSpace(pl)

	// split request payload to separate command from command payload
	payloadSplt := strings.Split(pl, " ")
	if len(payloadSplt) != 2 {
		log.Printf("ssh: invalid request length: %d", len(payloadSplt))
		closeWrite("ssh: invalid request: wrong length", channel)
		return
	}

	cmd := strings.TrimSpace(payloadSplt[0])
	payload := strings.TrimSpace(payloadSplt[1])

	switch cmd {
	case "sign-public-key":
		log.Printf("Got sign-public-key request")

		// Parse signing request
		// TODO: use real data
		sr, err := NewRequestFromClientRequest("ip", "username", []byte(payload))
		if err != nil {
			log.Printf("Cannot unmarshal payload: %s", err)
			closeWrite("ssh: invalid request: invalid payload", channel)
			return
		}

		// Verify signature against public key
		err = sr.PublicKey.Verify(sr.PublicKey.Marshal(), sr.Signature)
		if err != nil {
			log.Printf("ssh: invalid request: signature invalid")
			closeWrite("ssh: invalid request: invalid signature", channel)
			return
		}

		// TODO: sign request and create response

		payload, err := sr.PayloadBytes()
		if err != nil {
			panic(err)
		}

		log.Print(payload)

		err = initGrpc("127.0.0.1", "username", payload)
		if err != nil {
			panic(err)
		}

		closeWrite("blablablabla", channel)
		return

	default:
		log.Printf("Invalid command %s", cmd)
		closeWrite("ssh: invalid command", channel)
		return
	}
}

func closeWrite(msg string, channel ssh.Channel) {
	channel.Write([]byte(msg + "\r\n"))
	channel.Close()

	log.Println("Channel closed")
}

func initGrpc(ip string, username string, requestData []byte) error {
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithInsecure())
	conn, err := grpc.Dial("127.0.0.1:7777", dialOpts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	signerClient := server.NewServerClient(conn)

	var callOpts []grpc.CallOption
	resp, err := signerClient.SignUserPublicKey(
		context.Background(),
		&server.SignUserPublicKeyRequest{
			Ip:          ip,
			Username:    username,
			RequestData: requestData,
		},
		callOpts...,
	)
	if err != nil {
		return err
	}

	fmt.Printf("%+v", resp)
	return nil
}
