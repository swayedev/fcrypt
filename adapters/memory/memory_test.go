package memory_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/swayedev/fcrypt"
	"github.com/swayedev/fcrypt/adapters/memory"
)

func TestMemoryAdapterKeyStore(t *testing.T) {
	store, err := memory.NewKeyStore()
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	key, err := store.Rotate(context.Background(), fcrypt.RotationPolicy{
		Passphrase: "adapter-passphrase",
		Version:    "adapter-v1",
	})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if key.Version() != "adapter-v1" {
		t.Fatalf("Version() = %q, want adapter-v1", key.Version())
	}
}

func TestMemoryAdapterKeyWrapper(t *testing.T) {
	wrapper, err := memory.NewKeyWrapper("adapter-wrapper", bytes.Repeat([]byte{7}, fcrypt.DefaultKeyLength))
	if err != nil {
		t.Fatalf("NewKeyWrapper() error = %v", err)
	}

	key := bytes.Repeat([]byte{8}, fcrypt.DefaultKeyLength)
	wrapped, err := wrapper.WrapKey(context.Background(), key, fcrypt.WrapOptions{})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	unwrapped, err := wrapper.UnwrapKey(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}
	if !bytes.Equal(unwrapped, key) {
		t.Fatalf("UnwrapKey() mismatch")
	}
}
