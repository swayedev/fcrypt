package fcrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// GenerateGCM generates a Galois/Counter Mode (GCM) cipher.AEAD and cipher.Block using the provided key.
func GenerateGCM(key []byte) (gcm cipher.AEAD, block cipher.Block, err error) {
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFailedToCreateGCM, err)
	}
	return
}

// GenerateGCMWithNonce generates a GCM cipher and a random nonce sized to gcm.NonceSize().
func GenerateGCMWithNonce(key []byte) (gcm cipher.AEAD, block cipher.Block, nonce []byte, err error) {
	gcm, block, err = GenerateGCM(key)
	if err != nil {
		return
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}
	return
}

// Encrypt encrypts the given data using the provided key and returns the encrypted result.
// The nonce is randomly generated and prepended to the encrypted data.
func Encrypt(data []byte, key []byte) ([]byte, error) {
	gcm, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts the given ciphertext using the provided key.
func Decrypt(data []byte, key []byte) ([]byte, error) {
	gcm, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ReEncrypt decrypts with oldKey and encrypts again with newKey.
func ReEncrypt(data []byte, oldKey []byte, newKey []byte) ([]byte, error) {
	decryptedData, err := Decrypt(data, oldKey)
	if err != nil {
		return nil, err
	}
	return Encrypt(decryptedData, newKey)
}

// Context-aware variants

func EncryptWithContext(ctx context.Context, data []byte, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := Encrypt(data, key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func DecryptWithContext(ctx context.Context, data []byte, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := Decrypt(data, key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func ReEncryptWithContext(ctx context.Context, data []byte, oldKey []byte, newKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := ReEncrypt(data, oldKey, newKey)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
