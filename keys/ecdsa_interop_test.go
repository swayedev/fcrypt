package keys_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/swayedev/fcrypt/keys"
)

func TestGenerateEcdsaPemKeysWithNamedCurves(t *testing.T) {
	tests := []struct {
		name string
		gen  func() ([]byte, []byte, error)
		bits int
	}{
		{"P-256", keys.GenerateEcdsaP256PemKeys, 256},
		{"P-384", keys.GenerateEcdsaP384PemKeys, 384},
		{"P-521", keys.GenerateEcdsaP521PemKeys, 521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatePEM, publicPEM, err := tt.gen()
			if err != nil {
				t.Fatalf("generate error = %v", err)
			}
			privateKey, err := keys.ParsePemPrivateKey(privatePEM)
			if err != nil {
				t.Fatalf("ParsePemPrivateKey() error = %v", err)
			}
			publicKey, err := keys.ParsePemPublicKey(publicPEM)
			if err != nil {
				t.Fatalf("ParsePemPublicKey() error = %v", err)
			}
			ecdsaPrivate, ok := privateKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", privateKey)
			}
			ecdsaPublic, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("public key type = %T, want *ecdsa.PublicKey", publicKey)
			}
			if ecdsaPrivate.Curve.Params().BitSize != tt.bits {
				t.Fatalf("private curve bits = %d, want %d", ecdsaPrivate.Curve.Params().BitSize, tt.bits)
			}
			if ecdsaPublic.Curve.Params().BitSize != tt.bits {
				t.Fatalf("public curve bits = %d, want %d", ecdsaPublic.Curve.Params().BitSize, tt.bits)
			}
		})
	}
}

func TestGenerateCertificateNamedEcdsaCurves(t *testing.T) {
	tests := []string{
		keys.AlgorithmECDSAP256,
		keys.AlgorithmECDSAP384,
		keys.AlgorithmECDSAP521,
	}
	for _, algorithm := range tests {
		t.Run(algorithm, func(t *testing.T) {
			cert, err := keys.GenerateCertificate(algorithm)
			if err != nil {
				t.Fatalf("GenerateCertificate() error = %v", err)
			}
			if cert.Algorithm() != algorithm {
				t.Fatalf("Algorithm() = %q, want %q", cert.Algorithm(), algorithm)
			}
			if _, err := cert.ParsePrivateKey(); err != nil {
				t.Fatalf("ParsePrivateKey() error = %v", err)
			}
			if _, err := cert.ParsePublicKey(); err != nil {
				t.Fatalf("ParsePublicKey() error = %v", err)
			}
		})
	}
}

func TestGenerateOpenSSHEcdsaNamedCurves(t *testing.T) {
	tests := []struct {
		name  string
		gen   func() ([]byte, []byte, error)
		curve elliptic.Curve
	}{
		{"P-256", keys.GenerateOpenSSHEcdsaKeys, elliptic.P256()},
		{"P-384", keys.GenerateOpenSSHEcdsaP384Keys, elliptic.P384()},
		{"P-521", keys.GenerateOpenSSHEcdsaP521Keys, elliptic.P521()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatePEM, publicSSH, err := tt.gen()
			if err != nil {
				t.Fatalf("generate error = %v", err)
			}
			privateKey, err := keys.ParsePemPrivateKey(privatePEM)
			if err != nil {
				t.Fatalf("ParsePemPrivateKey() error = %v", err)
			}
			publicKey, err := keys.ParseOpenSSHPublicKey(publicSSH)
			if err != nil {
				t.Fatalf("ParseOpenSSHPublicKey() error = %v", err)
			}
			if privateKey.(*ecdsa.PrivateKey).Curve.Params().BitSize != tt.curve.Params().BitSize {
				t.Fatalf("private curve mismatch")
			}
			if publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize != tt.curve.Params().BitSize {
				t.Fatalf("public curve mismatch")
			}
		})
	}
}
