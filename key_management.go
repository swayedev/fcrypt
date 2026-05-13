package fcrypt

import (
	"context"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// KDFConfig controls passphrase-based key derivation.
type KDFConfig struct {
	SaltLength int
	KeyLength  int
	ScryptN    int
	ScryptR    int
	ScryptP    int
}

// DefaultKDFConfig returns the default scrypt configuration used by fcrypt.
func DefaultKDFConfig() KDFConfig {
	return KDFConfig{
		SaltLength: 16,
		KeyLength:  DefaultKeyLength,
		ScryptN:    ScryptN,
		ScryptR:    ScryptR,
		ScryptP:    ScryptP,
	}
}

func (c KDFConfig) withDefaults() KDFConfig {
	d := DefaultKDFConfig()
	if c.SaltLength <= 0 {
		c.SaltLength = d.SaltLength
	}
	if c.KeyLength <= 0 {
		c.KeyLength = d.KeyLength
	}
	if c.ScryptN <= 0 {
		c.ScryptN = d.ScryptN
	}
	if c.ScryptR <= 0 {
		c.ScryptR = d.ScryptR
	}
	if c.ScryptP <= 0 {
		c.ScryptP = d.ScryptP
	}
	return c
}

func (c KDFConfig) validate() error {
	if c.KeyLength < MinKeyLength {
		return ErrKeyLengthTooShort
	}
	if c.SaltLength <= 0 || c.ScryptN <= 0 || c.ScryptR <= 0 || c.ScryptP <= 0 {
		return ErrInvalidRotationPolicy
	}
	return nil
}

// GenerateKeyWithConfig derives a key with caller-provided KDF parameters.
func GenerateKeyWithConfig(passphrase string, salt []byte, config KDFConfig) ([]byte, error) {
	config = config.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	keyBytes, err := scrypt.Key([]byte(passphrase), salt, config.ScryptN, config.ScryptR, config.ScryptP, config.KeyLength)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// RotationPolicy describes how a new versioned key should be derived and stored.
type RotationPolicy struct {
	Passphrase string
	Algorithm  string
	KDF        KDFConfig
	Version    string
}

func (p RotationPolicy) normalize() RotationPolicy {
	if p.Algorithm == "" {
		p.Algorithm = "AES-GCM"
	}
	p.KDF = p.KDF.withDefaults()
	return p
}

func (p RotationPolicy) validate() error {
	if p.Passphrase == "" {
		return fmt.Errorf("%w: passphrase is required", ErrInvalidRotationPolicy)
	}
	return p.KDF.validate()
}

// KeyStore retrieves and stores versioned keys.
type KeyStore interface {
	Put(ctx context.Context, key Key) error
	Get(ctx context.Context, version string) (Key, error)
	Current(ctx context.Context) (Key, error)
	Rotate(ctx context.Context, policy RotationPolicy) (Key, error)
}

// RotateKeyWithContext derives and stores a new key using a KeyStore.
func RotateKeyWithContext(ctx context.Context, store KeyStore, policy RotationPolicy) (Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, fmt.Errorf("%w: nil key store", ErrInvalidRotationPolicy)
	}
	return store.Rotate(ctx, policy)
}

func deriveRotatedKey(policy RotationPolicy) (Key, error) {
	policy = policy.normalize()
	if err := policy.validate(); err != nil {
		return nil, err
	}
	salt, err := GenerateSalt(policy.KDF.SaltLength)
	if err != nil {
		return nil, err
	}
	keyBytes, err := GenerateKeyWithConfig(policy.Passphrase, salt, policy.KDF)
	if err != nil {
		return nil, err
	}
	version := policy.Version
	if version == "" {
		version = newKeyVersion()
	}
	return NewFcryptKey(version, salt, policy.Algorithm, keyBytes), nil
}

func cloneKey(key Key) (Key, error) {
	if key == nil || key.Version() == "" || len(key.KeyBytes()) == 0 {
		return nil, ErrInvalidKey
	}
	return NewFcryptKey(key.Version(), cloneBytes(key.Salt()), key.Algo(), cloneBytes(key.KeyBytes())), nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
