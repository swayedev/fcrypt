package fcrypt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/swayedev/fcrypt"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// Generates a PEM-encoded RSA private key.
func generateRSAPrivateKeyPEM() []byte {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privPEM
}

// Generates a PEM-encoded RSA public key.
func generateRSAPublicKeyPEM() []byte {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return pubPEM
}

// Generates a PEM-encoded ECDSA private key.
func generateECDSAPrivateKeyPEM() []byte {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKeyBytes, _ := x509.MarshalECPrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privPEM
}

// Generates a PEM-encoded ECDSA public key.
func generateECDSAPublicKeyPEM() []byte {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return pubPEM
}

// Generates a PEM-encoded Ed25519 private key.
func generateEd25519PrivateKeyPEM() []byte {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	privKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privPEM
}

// Generates a PEM-encoded Ed25519 public key.
func generateEd25519PublicKeyPEM() []byte {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return pubPEM
}

// Generates a PEM-encoded X25519 private key.
func generateX25519PrivateKeyPEM() []byte {
	var privKey [curve25519.ScalarSize]byte
	_, _ = rand.Read(privKey[:])
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PRIVATE KEY",
		Bytes: privKey[:],
	})
	return privPEM
}

// Generates a PEM-encoded X25519 public key.
func generateX25519PublicKeyPEM() []byte {
	var pubKey [curve25519.PointSize]byte
	_, _ = rand.Read(pubKey[:])
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PUBLIC KEY",
		Bytes: pubKey[:],
	})
	return pubPEM
}

// Generates an OpenSSH-encoded RSA public key.
func generateOpenSSHRSAKey() []byte {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey, _ := ssh.NewPublicKey(&privKey.PublicKey)
	return ssh.MarshalAuthorizedKey(pubKey)
}

// Generates an OpenSSH-encoded Ed25519 public key.
func generateOpenSSHEd25519Key() []byte {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubSSHKey, _ := ssh.NewPublicKey(pubKey)
	return ssh.MarshalAuthorizedKey(pubSSHKey)
}

func TestParsePemPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{"RSA Private Key", generateRSAPrivateKeyPEM(), false},
		{"ECDSA Private Key", generateECDSAPrivateKeyPEM(), false},
		{"Ed25519 Private Key", generateEd25519PrivateKeyPEM(), false},
		{"X25519 Private Key", generateX25519PrivateKeyPEM(), false},
		{"Invalid Private Key", []byte("invalid data"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fcrypt.ParsePemPrivateKey(tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePemPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePemPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{"RSA Public Key", generateRSAPublicKeyPEM(), false},
		{"ECDSA Public Key", generateECDSAPublicKeyPEM(), false},
		{"Ed25519 Public Key", generateEd25519PublicKeyPEM(), false},
		{"X25519 Public Key", generateX25519PublicKeyPEM(), false},
		{"Invalid Public Key", []byte("invalid data"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fcrypt.ParsePemPublicKey(tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePemPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOpenSSHPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		sshData []byte
		wantErr bool
	}{
		{"OpenSSH RSA Key", generateRSAPrivateKeyPEM(), false},
		{"OpenSSH Ed25519 Key", generateEd25519PrivateKeyPEM(), false},
		{"Invalid SSH Key", []byte("invalid data"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fcrypt.ParseOpenSSHPrivateKey(tt.sshData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOpenSSHPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOpenSSHPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		sshData []byte
		wantErr bool
	}{
		{"OpenSSH RSA Key", generateOpenSSHRSAKey(), false},
		{"OpenSSH Ed25519 Key", generateOpenSSHEd25519Key(), false},
		{"Invalid SSH Key", []byte("invalid data"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fcrypt.ParseOpenSSHPublicKey(tt.sshData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOpenSSHPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
