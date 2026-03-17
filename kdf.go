package fcrypt

import (
	"crypto/rand"

	"golang.org/x/crypto/scrypt"
)

// GenerateSalt generates a random salt of the specified length.
// It uses the crypto/rand package to generate cryptographically secure random bytes.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateKey generates a key using the provided passphrase, salt, and key length.
// It uses the scrypt key derivation function to derive the key from the passphrase and salt.
func GenerateKey(passphrase string, salt []byte, keyLength int) ([]byte, error) {
	if keyLength <= MinKeyLength {
		return nil, ErrKeyLengthTooShort
	}
	keyBytes, err := scrypt.Key([]byte(passphrase), salt, ScryptN, ScryptR, ScryptP, keyLength)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// GenerateSaltAndKey generates the salt and key using the provided passphrase and key length.
// It first generates the salt of the specified length and then derives the key using that salt.
func GenerateSaltAndKey(passphrase string, saltLength int, keyLength int) ([]byte, []byte, error) {
	salt, err := GenerateSalt(saltLength)
	if err != nil {
		return nil, nil, err
	}

	key, err := GenerateKey(passphrase, salt, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return salt, key, nil
}
