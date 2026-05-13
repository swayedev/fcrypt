package fcrypt

import (
	"context"
	"fmt"
	"sync"
)

// MemoryKeyStore is a dependency-free KeyStore implementation for tests,
// local development, and simple embedded use.
type MemoryKeyStore struct {
	mu      sync.RWMutex
	keys    map[string]Key
	current string
}

// NewMemoryKeyStore creates an empty in-memory key store.
func NewMemoryKeyStore(keys ...Key) (*MemoryKeyStore, error) {
	store := &MemoryKeyStore{keys: make(map[string]Key)}
	for _, key := range keys {
		if err := store.Put(context.Background(), key); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// Put stores a key version and marks it as current.
func (s *MemoryKeyStore) Put(ctx context.Context, key Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cloned, err := cloneKey(key)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[cloned.Version()] = cloned
	s.current = cloned.Version()
	return nil
}

// Get retrieves a key by version.
func (s *MemoryKeyStore) Get(ctx context.Context, version string) (Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if version == "" {
		return nil, fmt.Errorf("%w: empty version", ErrKeyNotFound)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, version)
	}
	return cloneKey(key)
}

// Current returns the current key.
func (s *MemoryKeyStore) Current(ctx context.Context) (Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == "" {
		return nil, ErrKeyNotFound
	}
	key, ok := s.keys[s.current]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, s.current)
	}
	return cloneKey(key)
}

// Rotate derives, stores, and marks a new key as current.
func (s *MemoryKeyStore) Rotate(ctx context.Context, policy RotationPolicy) (Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := deriveRotatedKey(policy)
	if err != nil {
		return nil, err
	}
	if err := s.Put(ctx, key); err != nil {
		return nil, err
	}
	return cloneKey(key)
}
