package fcrypt

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
)

// WrapOptions configures key wrapping operations.
type WrapOptions struct {
	KeyID     string
	Algorithm string
	AAD       []byte
}

// WrappedKey stores an encrypted data-encryption key and metadata needed to unwrap it.
type WrappedKey struct {
	KeyID      string
	Algorithm  string
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
}

// KeyWrapper wraps and unwraps data-encryption keys.
type KeyWrapper interface {
	WrapKey(ctx context.Context, plaintextKey []byte, opts WrapOptions) (WrappedKey, error)
	UnwrapKey(ctx context.Context, wrapped WrappedKey) ([]byte, error)
}

// LocalKeyWrapper is an AES-GCM KeyWrapper backed by a local wrapping key.
type LocalKeyWrapper struct {
	keyID string
	key   []byte
}

// NewLocalKeyWrapper creates a local AES-GCM key wrapper.
func NewLocalKeyWrapper(keyID string, wrappingKey []byte) (*LocalKeyWrapper, error) {
	if keyID == "" || len(wrappingKey) == 0 {
		return nil, ErrInvalidKey
	}
	if _, _, err := GenerateGCM(wrappingKey); err != nil {
		return nil, err
	}
	return &LocalKeyWrapper{keyID: keyID, key: cloneBytes(wrappingKey)}, nil
}

// WrapKey encrypts plaintextKey with the local wrapping key.
func (w *LocalKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, opts WrapOptions) (WrappedKey, error) {
	if err := ctx.Err(); err != nil {
		return WrappedKey{}, err
	}
	if len(plaintextKey) == 0 {
		return WrappedKey{}, ErrInvalidKey
	}

	aead, _, err := GenerateGCM(w.key)
	if err != nil {
		return WrappedKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return WrappedKey{}, fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}

	keyID := opts.KeyID
	if keyID == "" {
		keyID = w.keyID
	}
	algorithm := opts.Algorithm
	if algorithm == "" {
		algorithm = "AES-GCM"
	}
	aad := cloneBytes(opts.AAD)

	return WrappedKey{
		KeyID:      keyID,
		Algorithm:  algorithm,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintextKey, aad),
		AAD:        aad,
	}, nil
}

// UnwrapKey decrypts a wrapped key with the local wrapping key.
func (w *LocalKeyWrapper) UnwrapKey(ctx context.Context, wrapped WrappedKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if wrapped.KeyID != "" && wrapped.KeyID != w.keyID {
		return nil, fmt.Errorf("%w: unexpected key id", ErrInvalidWrappedKey)
	}
	if wrapped.Algorithm != "" && wrapped.Algorithm != "AES-GCM" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, wrapped.Algorithm)
	}

	aead, _, err := GenerateGCM(w.key)
	if err != nil {
		return nil, err
	}
	if len(wrapped.Nonce) != aead.NonceSize() || len(wrapped.Ciphertext) <= aead.Overhead() {
		return nil, ErrInvalidWrappedKey
	}

	plaintext, err := aead.Open(nil, wrapped.Nonce, wrapped.Ciphertext, wrapped.AAD)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}
	return plaintext, nil
}
