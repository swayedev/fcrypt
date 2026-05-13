// Package memory provides the no-dependency fcrypt memory adapter.
//
// It is useful for users who do not have a secret manager or KMS, and for
// tests/local development that should use the same adapter-shaped API as
// external backends.
package memory

import "github.com/swayedev/fcrypt"

// KeyStore is the in-memory fcrypt KeyStore implementation.
type KeyStore = fcrypt.MemoryKeyStore

// KeyWrapper is the local AES-GCM key wrapper implementation.
type KeyWrapper = fcrypt.LocalKeyWrapper

// NewKeyStore creates an empty in-memory key store.
func NewKeyStore(keys ...fcrypt.Key) (*KeyStore, error) {
	return fcrypt.NewMemoryKeyStore(keys...)
}

// NewKeyWrapper creates a local AES-GCM key wrapper.
func NewKeyWrapper(keyID string, wrappingKey []byte) (*KeyWrapper, error) {
	return fcrypt.NewLocalKeyWrapper(keyID, wrappingKey)
}
