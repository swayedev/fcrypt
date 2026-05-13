package fcrypt

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// RotateKey derives and stores a new versioned key in the provided store.
//
// It generates a new random salt, derives a key using scrypt (GenerateKey), and stores
// the resulting Key under a new version string.
//
// The returned version is the identifier used as the map key.
func RotateKey(passphrase string, store map[string]Key, keyLength int) (string, error) {
	key, err := deriveRotatedKey(RotationPolicy{
		Passphrase: passphrase,
		KDF: KDFConfig{
			SaltLength: 16,
			KeyLength:  keyLength,
		},
	})
	if err != nil {
		return "", err
	}
	store[key.Version()] = key
	return key.Version(), nil
}

func newKeyVersion() string {
	// time component for ordering + random component for uniqueness
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
