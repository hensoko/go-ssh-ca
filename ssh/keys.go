package ssh

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// ReadSSHAuthorizedKeys reads multiple authorized keys from given directory. Keys are stored in a map by username and
// public key.
func ReadSSHAuthorizedKeys(authorizedKeysDir string) (map[string]map[string]bool, error) {
	_, err := os.Stat(authorizedKeysDir)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("authorized keys directory does not exist")
	}

	authorizedKeysMap := map[string]map[string]bool{}

	files, err := filepath.Glob(path.Join(authorizedKeysDir, "*"))
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

// ReadSSHPrivateKey reads a private key and returns a ssh.Signer
func ReadSSHPrivateKey(path string) (ssh.Signer, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("ssh: private key file not found")
	}

	if err != nil {
		return nil, err
	}

	hostKeyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	return hostKey, nil
}
