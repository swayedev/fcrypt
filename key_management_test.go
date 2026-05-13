package fcrypt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/swayedev/fcrypt"
)

func TestMemoryKeyStoreRotateAndLookup(t *testing.T) {
	ctx := context.Background()
	store, err := fcrypt.NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("NewMemoryKeyStore() error = %v", err)
	}

	key, err := store.Rotate(ctx, fcrypt.RotationPolicy{
		Passphrase: "correct horse battery staple",
		KDF: fcrypt.KDFConfig{
			KeyLength: fcrypt.DefaultKeyLength,
		},
		Version: "v1",
	})
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if key.Version() != "v1" {
		t.Fatalf("Version() = %q, want v1", key.Version())
	}

	current, err := store.Current(ctx)
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if current.Version() != key.Version() {
		t.Fatalf("Current() = %q, want %q", current.Version(), key.Version())
	}

	got, err := store.Get(ctx, "v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got.KeyBytes(), key.KeyBytes()) {
		t.Fatalf("Get() returned wrong key bytes")
	}
}

func TestMemoryKeyStoreReturnsCopies(t *testing.T) {
	ctx := context.Background()
	key := fcrypt.NewFcryptKey("v1", []byte("salt"), "AES-GCM", bytes.Repeat([]byte{1}, fcrypt.DefaultKeyLength))
	store, err := fcrypt.NewMemoryKeyStore(key)
	if err != nil {
		t.Fatalf("NewMemoryKeyStore() error = %v", err)
	}

	got, err := store.Get(ctx, "v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	gotBytes := got.KeyBytes()
	gotBytes[0] ^= 0xff

	again, err := store.Get(ctx, "v1")
	if err != nil {
		t.Fatalf("Get() again error = %v", err)
	}
	if bytes.Equal(gotBytes, again.KeyBytes()) {
		t.Fatalf("store exposed mutable key bytes")
	}
}

func TestRotateKeyWithContext(t *testing.T) {
	ctx := context.Background()
	store, err := fcrypt.NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("NewMemoryKeyStore() error = %v", err)
	}

	key, err := fcrypt.RotateKeyWithContext(ctx, store, fcrypt.RotationPolicy{
		Passphrase: "passphrase",
		Version:    "ctx-v1",
	})
	if err != nil {
		t.Fatalf("RotateKeyWithContext() error = %v", err)
	}
	if key.Version() != "ctx-v1" {
		t.Fatalf("Version() = %q, want ctx-v1", key.Version())
	}

	_, err = fcrypt.RotateKeyWithContext(ctx, store, fcrypt.RotationPolicy{})
	if !errors.Is(err, fcrypt.ErrInvalidRotationPolicy) {
		t.Fatalf("RotateKeyWithContext(empty policy) error = %v, want ErrInvalidRotationPolicy", err)
	}
}

func TestLocalKeyWrapper(t *testing.T) {
	ctx := context.Background()
	wrapper, err := fcrypt.NewLocalKeyWrapper("local-v1", bytes.Repeat([]byte{9}, fcrypt.DefaultKeyLength))
	if err != nil {
		t.Fatalf("NewLocalKeyWrapper() error = %v", err)
	}

	plaintextKey := bytes.Repeat([]byte{4}, fcrypt.DefaultKeyLength)
	wrapped, err := wrapper.WrapKey(ctx, plaintextKey, fcrypt.WrapOptions{AAD: []byte("file-id:1")})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	if bytes.Equal(wrapped.Ciphertext, plaintextKey) {
		t.Fatalf("wrapped key contains plaintext key")
	}

	unwrapped, err := wrapper.UnwrapKey(ctx, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}
	if !bytes.Equal(unwrapped, plaintextKey) {
		t.Fatalf("UnwrapKey() mismatch")
	}

	wrapped.Ciphertext[0] ^= 0xff
	_, err = wrapper.UnwrapKey(ctx, wrapped)
	if !errors.Is(err, fcrypt.ErrAuthenticationFailed) {
		t.Fatalf("UnwrapKey(tampered) error = %v, want ErrAuthenticationFailed", err)
	}
}
