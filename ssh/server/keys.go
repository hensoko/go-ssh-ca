package server

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

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
