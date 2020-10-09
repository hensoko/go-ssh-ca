package bastion

import (
	"context"
	"fmt"
	"go-ssh-ca/api"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type User struct {
	Username   string
	LastAccess time.Time
}

type Bastion struct {
	api.UnimplementedBastionServer

	l          *zerolog.Logger
	sessions   map[string]User // TODO: not persistent
	sessionMux *sync.RWMutex
}

func NewBastion(l *zerolog.Logger) *Bastion {
	return &Bastion{
		l:          l,
		sessions:   make(map[string]User),
		sessionMux: &sync.RWMutex{},
	}
}

func (b *Bastion) getSession(sessionID uuid.UUID) (user *User, err error) {
	b.sessionMux.RUnlock()

	userTmp, ok := b.sessions[sessionID.String()]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	return &userTmp, nil
}

func (b *Bastion) createSession(username string) (*uuid.UUID, error) {
	sessionID := uuid.New()

	b.sessionMux.Lock()
	defer b.sessionMux.Unlock()

	if _, ok := b.sessions[sessionID.String()]; ok {
		return nil, fmt.Errorf("session %q already exists", sessionID)
	}

	b.sessions[sessionID.String()] = User{username, time.Now()}

	return &sessionID, nil
}

func (b Bastion) Authenticate(ctx context.Context, in *api.AuthenticateRequest) (out *api.AuthenticateResponse, err error) {
	b.l.Info().Msgf("New authentication request from user %q", in.GetUsername())

	// TODO: verify username and password

	sessionID, err := b.createSession(in.GetUsername())
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %s", err)
	}

	b.l.Info().Msgf("Created session %q for user %q", sessionID, in.GetUsername())
	return &api.AuthenticateResponse{
		SessionId: uuid.New().String(),
	}, nil
}

func (b Bastion) SignPublicKey(ctx context.Context, in *api.SignPublicKeyRequest) (out *api.SignPublicKeyResponse, err error) {
	sessionID, err := uuid.Parse(in.SessionId)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %s", err)
	}

	session, err := b.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	b.l.Info().Msgf("New sign public key request from user %q", session.Username)

	return nil, fmt.Errorf("not implemented")
}
