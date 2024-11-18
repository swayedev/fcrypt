package fcrypt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Parser for PEM certs: parses the private key and public key from the byte slice.

// ParsePemPrivateKey parses a PEM-encoded private key and returns the corresponding private key object.
// It supports PKCS#1, PKCS#8, and EC private keys.
func ParsePemPrivateKey(pemPrivateKey []byte) (any, error) {
	block, _ := pem.Decode(pemPrivateKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	var priKey any
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		priKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		priKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		priKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return priKey, nil
}

// ParsePemPublicKey decodes a PEM-encoded public key and returns the parsed public key.
// It supports PKIX, RSA, DSA, and EC public keys.
func ParsePemPublicKey(pemPublicKey []byte) (any, error) {
	block, _ := pem.Decode(pemPublicKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pubKey, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// parseOpenSSHPrivateKey handles the parsing of OpenSSH private keys.
func ParseOpenSSHPrivateKey(sshBytes []byte) (any, error) {
	parsedKey, err := ssh.ParseRawPrivateKey(sshBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenSSH private key: %v", err)
	}

	switch key := parsedKey.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey, *rsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported OpenSSH private key type: %T", key)
	}
}
