package gcpkms_test

import (
	"context"
	"testing"

	"github.com/swayedev/fcrypt"
	"github.com/swayedev/fcrypt/adapters/gcpkms"
)

type fakeClient struct{}

func (fakeClient) Encrypt(ctx context.Context, keyName string, plaintext []byte, aad []byte) ([]byte, error) {
	return append([]byte("gcp:"), plaintext...), nil
}

func (fakeClient) Decrypt(ctx context.Context, keyName string, ciphertext []byte, aad []byte) ([]byte, error) {
	return ciphertext[4:], nil
}

func TestAdapter(t *testing.T) {
	adapter, err := gcpkms.New(fakeClient{}, "projects/p/locations/l/keyRings/r/cryptoKeys/k")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	wrapped, err := adapter.WrapKey(t.Context(), []byte("data-key"), fcrypt.WrapOptions{AAD: []byte("aad")})
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
