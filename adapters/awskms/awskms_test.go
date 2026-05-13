package awskms_test

import (
	"context"
	"testing"

	"github.com/swayedev/fcrypt"
	"github.com/swayedev/fcrypt/adapters/awskms"
)

type fakeClient struct{}

func (fakeClient) Encrypt(ctx context.Context, keyID string, plaintext []byte, encryptionContext map[string]string) ([]byte, error) {
	return append([]byte("aws:"), plaintext...), nil
}

func (fakeClient) Decrypt(ctx context.Context, ciphertext []byte, encryptionContext map[string]string) ([]byte, error) {
	return ciphertext[4:], nil
}

func TestAdapter(t *testing.T) {
	adapter, err := awskms.New(fakeClient{}, "key", map[string]string{"app": "fcrypt"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	wrapped, err := adapter.WrapKey(t.Context(), []byte("data-key"), fcrypt.WrapOptions{})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	unwrapped, err := adapter.UnwrapKey(t.Context(), wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}
	if string(unwrapped) != "data-key" {
		t.Fatalf("UnwrapKey() = %q", unwrapped)
	}
}
