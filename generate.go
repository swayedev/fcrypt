package fcrypt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

const (
	AlgorithmRSA     = "RSA"
	AlgorithmED25519 = "ED25519"
	AlgorithmECDSA   = "ECDSA"
	AlgorithmX25519  = "X25519"
	AlgorithmRSAOAEP = "RSA-OAEP"
)

type Certificate interface {
	SetPrivateKey(privateKey []byte)
	PrivateKey() []byte
	PrivateKeyString() string
	ParsePrivateKey() (interface{}, error)
	SetPublicKey(publicKey []byte)
	PublicKey() []byte
	PublicKeyString() string
	ParsePublicKey() (interface{}, error)
	SetAlgorithm(algorithm string)
	Algorithm() string
}

type CertificateKey struct {
	privateKey []byte
	publicKey  []byte
	algorithm  string
}

func (c *CertificateKey) SetPrivateKey(privateKey []byte) {
	c.privateKey = privateKey
}

func (c *CertificateKey) PrivateKey() []byte {
	return c.privateKey
}

func (c *CertificateKey) PrivateKeyString() string {
	return string(c.privateKey)
}

func (c *CertificateKey) SetPublicKey(publicKey []byte) {
	c.publicKey = publicKey
}

func (c *CertificateKey) PublicKey() []byte {
	return c.publicKey
}

func (c *CertificateKey) PublicKeyString() string {
	return string(c.publicKey)
}

func (c *CertificateKey) SetAlgorithm(algorithm string) {
	c.algorithm = algorithm
}

func (c *CertificateKey) Algorithm() string {
	return c.algorithm
}

func (c *CertificateKey) ParsePrivateKey() (interface{}, error) {
	return ParsePemPrivateKey(c.privateKey)
}

func (c *CertificateKey) ParsePublicKey() (interface{}, error) {
	return ParsePemPublicKey(c.publicKey)
}

func GenerateCertificate(algorithm string) (Certificate, error) {
	switch algorithm {
	case AlgorithmRSA:
		return generateCertificateKey(GenerateRsaPemKeys, algorithm)
	case AlgorithmED25519:
		return generateCertificateKey(GenerateEd25519PemKeys, algorithm)
	case AlgorithmECDSA:
		return generateCertificateKey(GenerateEcdsaPemKeys, algorithm)
	case AlgorithmX25519:
		return generateCertificateKey(GenerateX25519PemKeys, algorithm)
	case AlgorithmRSAOAEP:
		return generateCertificateKey(GenerateRsaOaepPemKeys, algorithm)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func generateCertificateKey(
	keyGenFunc func() ([]byte, []byte, error),
	algorithm string,
) (Certificate, error) {
	privateKey, publicKey, err := keyGenFunc()
	if err != nil {
		return nil, err
	}

	cert := &CertificateKey{
		privateKey: privateKey,
		publicKey:  publicKey,
		algorithm:  algorithm,
	}
	return cert, nil
}

// Generate RSA Key
func GenerateRsaPemKeys() (privKeyPEM []byte, pubKeyPEM []byte, err error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privKeyPEM, pubKeyPEM, nil
}

// Generate RSA-OAEP Key (Same as RSA but used for encryption)
func GenerateRsaOaepPemKeys() ([]byte, []byte, error) {
	return GenerateRsaPemKeys()
}

// Generate ED25519 Key
func GenerateEd25519PemKeys() (privKeyPEM []byte, pubKeyPEM []byte, err error) {
	pubKey, priKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	privKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privKeyPEM, pubKeyPEM, nil
}

// Generate ECDSA Key
func GenerateEcdsaPemKeys() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privKeyPEM, pubKeyPEM, nil
}

// Generate X25519 Key
func GenerateX25519PemKeys() ([]byte, []byte, error) {
	// Generate private key
	var privKey [32]byte
	_, err := rand.Read(privKey[:])
	if err != nil {
		return nil, nil, err
	}

	// Derive public key
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// Encode to PEM
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PRIVATE KEY",
		Bytes: privKey[:],
	})

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PUBLIC KEY",
		Bytes: pubKey[:],
	})

	return privKeyPEM, pubKeyPEM, nil
}

// // Generates an RSA private and public key in PEM and OpenSSH format.
func GenerateOpenSSHRSAKeys() ([]byte, []byte, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key to PEM format
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate the public key in OpenSSH format
	pubKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := ssh.MarshalAuthorizedKey(pubKey)

	return privPEM, pubPEM, nil
}

// // Generates an Ed25519 private and public key in PEM and OpenSSH format.
func GenerateOpenSSHEd25519Keys() ([]byte, []byte, error) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key to PEM format using PKCS#8
	privPEM, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	privBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privPEM,
	}
	privPEMBytes := pem.EncodeToMemory(&privBlock)

	// Generate the public key in OpenSSH format
	pubSSHKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	pubPEM := ssh.MarshalAuthorizedKey(pubSSHKey)

	return privPEMBytes, pubPEM, nil
}
