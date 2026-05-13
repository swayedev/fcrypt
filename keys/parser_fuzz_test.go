package keys

import "testing"

func FuzzParsePemPrivateKey(f *testing.F) {
	privateKey, _, err := GenerateEd25519PemKeys()
	if err != nil {
		f.Fatalf("GenerateEd25519PemKeys() seed error = %v", err)
	}
	f.Add(privateKey)
	f.Add([]byte("not pem"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePemPrivateKey(data)
	})
}

func FuzzParsePemPublicKey(f *testing.F) {
	_, publicKey, err := GenerateEd25519PemKeys()
	if err != nil {
		f.Fatalf("GenerateEd25519PemKeys() seed error = %v", err)
	}
	f.Add(publicKey)
	f.Add([]byte("not pem"))
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePemPublicKey(data)
	})
}

func FuzzParseOpenSSHPublicKey(f *testing.F) {
	_, publicKey, err := GenerateOpenSSHEd25519Keys()
	if err != nil {
		f.Fatalf("GenerateOpenSSHEd25519Keys() seed error = %v", err)
	}
	f.Add(publicKey)
	f.Add([]byte("not ssh"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseOpenSSHPublicKey(data)
	})
}
