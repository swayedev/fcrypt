package azurekeyvault_test

import (
	"context"
	"testing"

	"github.com/swayedev/fcrypt"
	"github.com/swayedev/fcrypt/adapters/azurekeyvault"
)

type fakeClient struct{}

func (fakeClient) WrapKey(ctx context.Context, keyID string, algorithm string, plaintext []byte) ([]byte, error) {
	return append([]byte("az:"), plaintext...), nil
}

func (fakeClient) UnwrapKey(ctx context.Context, keyID string, algorithm string, ciphertext []byte) ([]byte, error) {
	return ciphertext[3:], nil
}

func TestAdapter(t *testing.T) {
	adapter, err := azurekeyvault.New(fakeClient{}, "https://vault/keys/key", "")
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
