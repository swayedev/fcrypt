// Package azurekeyvault provides an SDK-neutral Azure Key Vault adapter.
package azurekeyvault

import (
	"context"
	"fmt"

	"github.com/swayedev/fcrypt"
)

// Client is the minimal Azure Key Vault behavior required by this adapter.
type Client interface {
	WrapKey(ctx context.Context, keyID string, algorithm string, plaintext []byte) ([]byte, error)
	UnwrapKey(ctx context.Context, keyID string, algorithm string, ciphertext []byte) ([]byte, error)
}

// Adapter wraps and unwraps data keys with Azure Key Vault.
type Adapter struct {
	client    Client
	keyID     string
	algorithm string
}

// New creates an Azure Key Vault adapter around a caller-supplied client.
func New(client Client, keyID string, algorithm string) (*Adapter, error) {
	if client == nil || keyID == "" {
		return nil, fcrypt.ErrInvalidKey
	}
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}
	return &Adapter{client: client, keyID: keyID, algorithm: algorithm}, nil
}

// WrapKey wraps plaintextKey with Azure Key Vault.
func (a *Adapter) WrapKey(ctx context.Context, plaintextKey []byte, opts fcrypt.WrapOptions) (fcrypt.WrappedKey, error) {
	if err := ctx.Err(); err != nil {
		return fcrypt.WrappedKey{}, err
	}
	if len(plaintextKey) == 0 {
		return fcrypt.WrappedKey{}, fcrypt.ErrInvalidKey
	}
	keyID := a.keyID
	if opts.KeyID != "" {
		keyID = opts.KeyID
	}
	algorithm := a.algorithm
	if opts.Algorithm != "" {
		algorithm = opts.Algorithm
	}
	ciphertext, err := a.client.WrapKey(ctx, keyID, algorithm, plaintextKey)
	if err != nil {
		return fcrypt.WrappedKey{}, fmt.Errorf("%w: %v", fcrypt.ErrInvalidWrappedKey, err)
	}
	return fcrypt.WrappedKey{KeyID: keyID, Algorithm: algorithm, Ciphertext: ciphertext, AAD: cloneBytes(opts.AAD)}, nil
}

// UnwrapKey unwraps wrapped with Azure Key Vault.
func (a *Adapter) UnwrapKey(ctx context.Context, wrapped fcrypt.WrappedKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keyID := a.keyID
	if wrapped.KeyID != "" {
		keyID = wrapped.KeyID
	}
	algorithm := a.algorithm
	if wrapped.Algorithm != "" {
		algorithm = wrapped.Algorithm
	}
	plaintext, err := a.client.UnwrapKey(ctx, keyID, algorithm, wrapped.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", fcrypt.ErrInvalidWrappedKey, err)
	}
	return plaintext, nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
