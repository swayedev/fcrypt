package parser

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Parser for PEM certs: parses the private key and public key from the byte slice.

// PemPrivateKey parses a PEM-encoded private key and returns the corresponding private key object.
// It takes a byte slice containing the PEM-encoded private key as input.
// The function returns the parsed private key object and an error if any occurred during parsing.
func PemPrivateKey(pemPrivateKey []byte) (any, error) {
	block, _ := pem.Decode(pemPrivateKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priKey, nil
}

// PemPublicKey decodes a PEM-encoded public key and returns the parsed public key.
// It takes a byte slice containing the PEM-encoded public key as input.
// The function returns the parsed public key and an error if any occurred during the parsing process.
func PemPublicKey(pemPublicKey []byte) (any, error) {
	// Decode the public key from PEM format
	block, _ := pem.Decode(pemPublicKey)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}
