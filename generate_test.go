package fcrypt_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/swayedev/fcrypt"
)

// WIP: Add more test cases to validate the GenerateCertificate function
func TestGenerateCertificate(t *testing.T) {
	// Test case 1: RSA algorithm
	algorithm := "RSA"
	cert, err := fcrypt.GenerateCertificate(algorithm)
	if err != nil {
		t.Errorf("GenerateCertificate() returned an error: %v", err)
	}

	if cert == nil {
		t.Errorf("GenerateCertificate() returned nil certificate for algorithm %s", algorithm)
	} else {
		if cert.Algorithm() != algorithm {
			t.Errorf("GenerateCertificate() returned a certificate with type %s, expected %s", cert.Algorithm(), algorithm)
		}

		// Additional assertions for RSA algorithm

	}

	// Test case 2: ED25519 algorithm
	algorithm = "ED25519"
	cert, err = fcrypt.GenerateCertificate(algorithm)
	if err != nil {
		t.Errorf("GenerateCertificate() returned an error: %v", err)
	}

	if cert == nil {
		t.Errorf("GenerateCertificate() returned nil certificate for algorithm %s", algorithm)
	} else {
		if cert.Algorithm() != algorithm {
			t.Errorf("GenerateCertificate() returned a certificate with type %s, expected %s", cert.Algorithm(), algorithm)
		}

		// Additional assertions for ED25519 algorithm

	}

	// Test case 3: Invalid algorithm
	algorithm = "InvalidAlgorithm"
	cert, err = fcrypt.GenerateCertificate(algorithm)
	if err != nil {
		t.Errorf("GenerateCertificate() returned an error: %v", err)
	}

	if cert != nil {
		t.Errorf("GenerateCertificate() returned non-nil certificate for invalid algorithm %s", algorithm)
	}
}

func TestGenerateEd25519PemKeys(t *testing.T) {
	privateKey, publicKey, err := fcrypt.GenerateEd25519PemKeys()
	if err != nil {
		t.Errorf("GenerateEd25519PemKeys() returned an error: %v", err)
	}

	// Decode the private key from PEM format
	block, _ := pem.Decode(privateKey)
	if block == nil {
		t.Errorf("private_key: pem.Decode() returned nil")
	}
	priKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("private_key: x509.ParsePKCS8PrivateKey() returned an error: %v", err)
	}

	// Decode the public key from PEM format
	block, _ = pem.Decode(publicKey)
	if block == nil {
		t.Errorf("public_key: pem.Decode() returned nil")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("public_key: x509.ParsePKIXPublicKey() returned an error: %v", err)
	}

	// Verify that the private key and public key are valid
	_, ok := priKey.(ed25519.PrivateKey)
	if !ok {
		t.Errorf("private_key: x509.ParsePKCS8PrivateKey() returned a private key of type %T, expected ed25519.PrivateKey", priKey)
	}
	_, ok = pubKey.(ed25519.PublicKey)
	if !ok {
		t.Errorf("public_key: x509.ParsePKIXPublicKey() returned a public key of type %T, expected ed25519.PublicKey", pubKey)
	}
}

func TestGenerateRsaPemKeys(t *testing.T) {
	privateKey, publicKey, err := fcrypt.GenerateRsaPemKeys()
	if err != nil {
		t.Errorf("GenerateRsaPemKeys() returned an error: %v", err)
	}

	// TODO: Add assertions to validate the generated keys
	// For example, you can check the length of the private and public keys,
	// or decode the keys and verify their format.

	// Example assertion:
	if len(privateKey) == 0 {
		t.Errorf("GenerateRsaPemKeys() returned an empty private key")
	}

	if len(publicKey) == 0 {
		t.Errorf("GenerateRsaPemKeys() returned an empty public key")
	}
}
