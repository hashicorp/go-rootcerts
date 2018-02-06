package rootcerts

import (
	"crypto/x509"
	"fmt"
	"os/exec"
	"path"

	homedir "github.com/mitchellh/go-homedir"
)

// LoadSystemCAs has special behavior on Darwin systems to work around
func LoadSystemCAs() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, keychain := range certKeychains() {
		err := addCertsFromKeychain(pool, keychain)
		if err != nil {
			return nil, err
		}
	}

	return pool, nil
}

func addCertsFromKeychain(pool *x509.CertPool, keychain string) error {
	cmd := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", keychain)
	data, err := cmd.Output()
	if err != nil {
		return err
	}

	if ok := pool.AppendCertsFromPEM(data); !ok {
		// https://github.com/golang/go/issues/23711
		return fmt.Errorf("Failed to add cert from %s. Is the common name a DNS compatible name?", keychain)
	}

	return nil
}

func certKeychains() []string {
	keychains := []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Library/Keychains/System.keychain",
	}
	home, err := homedir.Dir()
	if err == nil {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")
		keychains = append(keychains, loginKeychain)
	}
	return keychains
}
