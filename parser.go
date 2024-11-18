package fcrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// decodePEMBlock decodes a PEM block and validates its type, if specified.
func decodePEMBlock(pemData []byte, expectedType string) (*pem.Block, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if expectedType != "" && block.Type != expectedType {
		return nil, fmt.Errorf("unexpected PEM block type: got %s, want %s", block.Type, expectedType)
	}
	return block, nil
}

// parseX25519PrivateKey handles parsing X25519 private keys from PEM blocks.
func parseX25519PrivateKey(block *pem.Block) ([]byte, error) {
	if block.Type != "X25519 PRIVATE KEY" || len(block.Bytes) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 private key")
	}
	return block.Bytes, nil
}

// parseX25519PublicKey handles parsing X25519 public keys from PEM blocks.
func parseX25519PublicKey(block *pem.Block) ([]byte, error) {
	if block.Type != "X25519 PUBLIC KEY" || len(block.Bytes) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 public key")
	}
	return block.Bytes, nil
}

// ParsePemPrivateKey parses PEM-encoded private keys and supports multiple formats.
func ParsePemPrivateKey(pemPrivateKey []byte) (interface{}, error) {
	block, err := decodePEMBlock(pemPrivateKey, "")
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "X25519 PRIVATE KEY":
		return parseX25519PrivateKey(block)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// ParsePemPublicKey parses PEM-encoded public keys and supports multiple formats.
func ParsePemPublicKey(pemPublicKey []byte) (interface{}, error) {
	block, err := decodePEMBlock(pemPublicKey, "")
	if err != nil {
		return nil, err
	}

	if block.Type == "X25519 PUBLIC KEY" {
		return parseX25519PublicKey(block)
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

// ParseOpenSSHPrivateKey parses OpenSSH private keys.
func ParseOpenSSHPrivateKey(sshBytes []byte) (interface{}, error) {
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

// ParseOpenSSHPublicKey parses OpenSSH public keys.
func ParseOpenSSHPublicKey(sshBytes []byte) (interface{}, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(sshBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenSSH public key: %v", err)
	}

	parsedKey, err := ssh.ParsePublicKey(pubKey.Marshal())
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenSSH public key: %v", err)
	}

	parsedCryptoKey := parsedKey.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	return convertToCryptoPublicKey(pubCrypto, pubKey.Type())
}

// convertToCryptoPublicKey converts ssh.PublicKey to its corresponding crypto.PublicKey.
func convertToCryptoPublicKey(pubCrypto crypto.PublicKey, keyType string) (interface{}, error) {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return convertRSAPublicKey(pubCrypto)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return convertECDSAPublicKey(pubCrypto)
	case ssh.KeyAlgoED25519:
		return convertED25519PublicKey(pubCrypto)
	default:
		return nil, fmt.Errorf("unsupported OpenSSH public key type: %s", keyType)
	}
}

func convertRSAPublicKey(pubCrypto crypto.PublicKey) (*rsa.PublicKey, error) {
	if rsaKey, ok := pubCrypto.(*rsa.PublicKey); ok {
		return rsaKey, nil
	}
	return nil, errors.New("not an RSA public key")
}

func convertECDSAPublicKey(pubCrypto crypto.PublicKey) (*ecdsa.PublicKey, error) {
	if ecdsaKey, ok := pubCrypto.(*ecdsa.PublicKey); ok {
		return ecdsaKey, nil
	}
	return nil, errors.New("not an ECDSA public key")
}

func convertED25519PublicKey(pubCrypto crypto.PublicKey) (ed25519.PublicKey, error) {
	if ed25519Key, ok := pubCrypto.(ed25519.PublicKey); ok {
		return ed25519Key, nil
	}
	return nil, errors.New("not an ED25519 public key")
}
