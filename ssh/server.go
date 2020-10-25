package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"path"

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
		go s.handleUserChannels(conn.Permissions.Extensions["client-ip"], conn.User(), chans)
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
			//TODO: this method can be used right now to check for existing usernames
			if authorizedKeysMap[c.User()] == nil {
				return nil, fmt.Errorf("unknown public key for %s", c.User())
			}

			if authorizedKeysMap[c.User()][string(pubKey.Marshal())] {
				return &ssh.Permissions{

					Extensions: map[string]string{
						// Record the ip address used for authentication.
						"client-ip": c.LocalAddr().String(),

						// Record the public key used for authentication.
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

func (s *Server) handleUserChannels(ipAddress string, username string, chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		go s.handleUserChannel(ipAddress, username, newChannel)
	}
}

func (s *Server) handleUserChannel(ipAddress string, username string, newChannel ssh.NewChannel) {
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
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

			s.handleUserExec(ipAddress, username, channel, req)
		}
	}(requests)
}

func (s *Server) handleUserExec(ipAddress string, username string, channel ssh.Channel, req *ssh.Request) {
	if len(req.Payload) == 0 {
		log.Print("ssh: invalid request: empty payload")
		closeWrite("ssh: invalid request: empty payload", channel)
		return
	}

	// split request payload to separate command from command payload
	payloadSplt := bytes.SplitN(req.Payload[4:], []byte(" "), 2)
	if len(payloadSplt) != 2 {
		log.Printf("ssh: invalid request length: %d", len(payloadSplt))
		closeWrite("ssh: invalid request: wrong length", channel)
		return
	}

	cmd := bytes.TrimSpace(payloadSplt[0])
	payload := bytes.TrimSpace(payloadSplt[1])

	switch string(cmd) {
	case "sign-public-key":
		log.Printf("Got sign-public-key request")

		// Parse signing request
		var sr SigningRequest
		err := json.Unmarshal(payload, &sr)
		if err != nil {
			log.Printf("Cannot unmarshal payload: %s", err)
			closeWrite("ssh: invalid request: invalid payload", channel)
			return
		}

		if sr.PublicKey == nil {
			log.Printf("empty publickey")
			closeWrite("ssh: invalid request: no public key", channel)
			return
		}

		if sr.Signature == nil {
			log.Printf("empty signature")
			closeWrite("ssh: invalid request: no signature", channel)
			return
		}

		// Verify signature against public key
		// TODO SECURITY: ensure public key belongs to authenticating user
		err = sr.PublicKey.Verify(sr.PublicKey.Marshal(), sr.Signature)
		if err != nil {
			log.Printf("ssh: invalid request: signature invalid")
			closeWrite("ssh: invalid request: invalid signature", channel)
			return
		}

		sr.IPAddress = ipAddress
		sr.Username = username

		// TODO: sign request and create response
		log.Printf("Making grpc request")
		err = s.makeGrpcSigningRequest(&sr)
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

func (s *Server) makeGrpcSigningRequest(req *SigningRequest) error {
	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts, grpc.WithInsecure())
	conn, err := grpc.Dial("127.0.0.1:7777", dialOpts...)
	if err != nil {
		return err
	}
	defer conn.Close()

	reqJson, err := json.Marshal(req)
	if err != nil {
		return err
	}

	log.Printf("reading private key")
	hostKey, err := ReadSSHPrivateKey(path.Join(s.c.BaseDir, s.c.HostKeyFile))
	if err != nil {
		return err
	}

	log.Printf("signing")
	signature, err := hostKey.Sign(rand.Reader, reqJson)
	if err != nil {
		return err
	}
	signatureJson, err := json.Marshal(signature)
	if err != nil {
		return err
	}

	log.Printf("sending")
	var callOpts []grpc.CallOption
	resp, err := server.NewServerClient(conn).SignUserPublicKey(
		context.Background(),
		&server.SignUserPublicKeyRequest{
			RequestData: reqJson,
			Signature:   signatureJson,
		},
		callOpts...,
	)
	if err != nil {
		return err
	}

	fmt.Printf("%+v", resp)
	return nil
}
