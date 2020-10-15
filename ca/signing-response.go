package ca

import (
	"time"

	"golang.org/x/crypto/ssh"
)

type SigningResponse struct {
	Certificate ssh.Certificate
	ValidUntil  time.Time
}
