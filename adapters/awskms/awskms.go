// Package awskms provides an SDK-neutral AWS KMS adapter.
package awskms

import (
	"context"
	"fmt"

	"github.com/swayedev/fcrypt"
)

// Client is the minimal AWS KMS behavior required by this adapter.
// Implement it with the AWS SDK type used by your application.
type Client interface {
	Encrypt(ctx context.Context, keyID string, plaintext []byte, encryptionContext map[string]string) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte, encryptionContext map[string]string) ([]byte, error)
}

// Adapter wraps and unwraps data keys with AWS KMS.
type Adapter struct {
	client            Client
	keyID             string
	encryptionContext map[string]string
}

// New creates an AWS KMS adapter around a caller-supplied client.
func New(client Client, keyID string, encryptionContext map[string]string) (*Adapter, error) {
	if client == nil || keyID == "" {
		return nil, fcrypt.ErrInvalidKey
	}
	return &Adapter{client: client, keyID: keyID, encryptionContext: cloneMap(encryptionContext)}, nil
}

// WrapKey wraps plaintextKey with AWS KMS.
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
	ciphertext, err := a.client.Encrypt(ctx, keyID, plaintextKey, a.encryptionContext)
	if err != nil {
		return fcrypt.WrappedKey{}, fmt.Errorf("%w: %v", fcrypt.ErrInvalidWrappedKey, err)
	}
	return fcrypt.WrappedKey{KeyID: keyID, Algorithm: "aws-kms", Ciphertext: ciphertext, AAD: opts.AAD}, nil
}

// UnwrapKey unwraps wrapped with AWS KMS.
func (a *Adapter) UnwrapKey(ctx context.Context, wrapped fcrypt.WrappedKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(wrapped.Ciphertext) == 0 {
		return nil, fcrypt.ErrInvalidWrappedKey
	}
	plaintext, err := a.client.Decrypt(ctx, wrapped.Ciphertext, a.encryptionContext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", fcrypt.ErrInvalidWrappedKey, err)
	}
	return plaintext, nil
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
