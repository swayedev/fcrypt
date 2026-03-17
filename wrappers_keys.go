package fcrypt

import "github.com/swayedev/fcrypt/keys"

// Deprecated: prefer importing github.com/swayedev/fcrypt/keys.

// ParsePemPrivateKey parses PEM-encoded private keys.
func ParsePemPrivateKey(pemPrivateKey []byte) (interface{}, error) {
	return keys.ParsePemPrivateKey(pemPrivateKey)
}

// ParsePemPublicKey parses PEM-encoded public keys.
func ParsePemPublicKey(pemPublicKey []byte) (interface{}, error) {
	return keys.ParsePemPublicKey(pemPublicKey)
}

// ParseOpenSSHPrivateKey parses OpenSSH private keys.
func ParseOpenSSHPrivateKey(sshBytes []byte) (interface{}, error) {
	return keys.ParseOpenSSHPrivateKey(sshBytes)
}

// ParseOpenSSHPublicKey parses OpenSSH public keys.
func ParseOpenSSHPublicKey(sshBytes []byte) (interface{}, error) {
	return keys.ParseOpenSSHPublicKey(sshBytes)
}

const (
	AlgorithmRSA     = keys.AlgorithmRSA
	AlgorithmED25519 = keys.AlgorithmED25519
	AlgorithmECDSA   = keys.AlgorithmECDSA
	AlgorithmX25519  = keys.AlgorithmX25519
	AlgorithmRSAOAEP = keys.AlgorithmRSAOAEP
)

type Certificate = keys.Certificate

type CertificateKey = keys.CertificateKey

func GenerateCertificate(algorithm string) (Certificate, error) {
	return keys.GenerateCertificate(algorithm)
}

func GenerateRsaPemKeys() ([]byte, []byte, error)         { return keys.GenerateRsaPemKeys() }
func GenerateRsaOaepPemKeys() ([]byte, []byte, error)     { return keys.GenerateRsaOaepPemKeys() }
func GenerateEd25519PemKeys() ([]byte, []byte, error)     { return keys.GenerateEd25519PemKeys() }
func GenerateEcdsaPemKeys() ([]byte, []byte, error)       { return keys.GenerateEcdsaPemKeys() }
func GenerateX25519PemKeys() ([]byte, []byte, error)      { return keys.GenerateX25519PemKeys() }
func GenerateOpenSSHRSAKeys() ([]byte, []byte, error)     { return keys.GenerateOpenSSHRSAKeys() }
func GenerateOpenSSHEd25519Keys() ([]byte, []byte, error) { return keys.GenerateOpenSSHEd25519Keys() }
