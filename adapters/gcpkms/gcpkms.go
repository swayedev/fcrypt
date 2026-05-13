// Package gcpkms provides an SDK-neutral Google Cloud KMS adapter.
package gcpkms

import (
	"context"
	"fmt"

	"github.com/swayedev/fcrypt"
)

// Client is the minimal Google Cloud KMS behavior required by this adapter.
type Client interface {
	Encrypt(ctx context.Context, keyName string, plaintext []byte, additionalAuthenticatedData []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyName string, ciphertext []byte, additionalAuthenticatedData []byte) ([]byte, error)
}

// Adapter wraps and unwraps data keys with Google Cloud KMS.
type Adapter struct {
	client  Client
	keyName string
}

// New creates a Google Cloud KMS adapter around a caller-supplied client.
func New(client Client, keyName string) (*Adapter, error) {
	if client == nil || keyName == "" {
		return nil, fcrypt.ErrInvalidKey
	}
	return &Adapter{client: client, keyName: keyName}, nil
}

// WrapKey wraps plaintextKey with Google Cloud KMS.
func (a *Adapter) WrapKey(ctx context.Context, plaintextKey []byte, opts fcrypt.WrapOptions) (fcrypt.WrappedKey, error) {
	if err := ctx.Err(); err != nil {
		return fcrypt.WrappedKey{}, err
	}
	if len(plaintextKey) == 0 {
		return fcrypt.WrappedKey{}, fcrypt.ErrInvalidKey
	}
	keyName := a.keyName
	if opts.KeyID != "" {
		keyName = opts.KeyID
	}
	ciphertext, err := a.client.Encrypt(ctx, keyName, plaintextKey, opts.AAD)
	if err != nil {
		return fcrypt.WrappedKey{}, fmt.Errorf("%w: %v", fcrypt.ErrInvalidWrappedKey, err)
	}
	return fcrypt.WrappedKey{KeyID: keyName, Algorithm: "gcp-kms", Ciphertext: ciphertext, AAD: cloneBytes(opts.AAD)}, nil
}

// UnwrapKey unwraps wrapped with Google Cloud KMS.
func (a *Adapter) UnwrapKey(ctx context.Context, wrapped fcrypt.WrappedKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keyName := a.keyName
	if wrapped.KeyID != "" {
		keyName = wrapped.KeyID
	}
	plaintext, err := a.client.Decrypt(ctx, keyName, wrapped.Ciphertext, wrapped.AAD)
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
