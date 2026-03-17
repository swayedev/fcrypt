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
	salt, err := GenerateSalt(16)
	if err != nil {
		return "", err
	}

	keyBytes, err := GenerateKey(passphrase, salt, keyLength)
	if err != nil {
		return "", err
	}

	version := newKeyVersion()
	store[version] = NewFcryptKey(version, salt, "AES-GCM", keyBytes)
	return version, nil
}

func newKeyVersion() string {
	// time component for ordering + random component for uniqueness
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}
