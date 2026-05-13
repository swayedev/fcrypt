# fcrypt Threat Model

This document describes what fcrypt is designed to protect, what it does not protect, and the security properties expected for the v1 API.

## Assets

- Plaintext bytes and files passed to encryption APIs.
- Data-encryption keys passed to `Encrypt`, file APIs, and stream APIs.
- Versioned keys managed through `KeyStore`.
- Wrapped data keys managed through `KeyWrapper` adapters.
- Encrypted file and stream records written by fcrypt.

## Expected Attackers

fcrypt assumes an attacker may be able to:

- Read ciphertext files, streams, or byte slices.
- Modify, truncate, replay, or corrupt ciphertext.
- Supply malformed encrypted files or streams to decryptors.
- Supply malformed PEM or OpenSSH key material to parsers.
- Observe error messages returned by fcrypt APIs.

fcrypt does not assume an attacker can:

- Read process memory.
- Read plaintext keys from the caller's key store, KMS, or secret manager.
- Compromise the operating system random number generator.
- Bypass access control in a caller's application.

## Security Properties

### Byte Encryption

`Encrypt` uses AES-GCM with random nonces from `crypto/rand`.

Properties:

- Confidentiality for plaintext when the key remains secret.
- Integrity and authentication for ciphertext.
- Tampering should fail during `Decrypt`.

Caller responsibilities:

- Use AES-compatible key lengths.
- Avoid reusing weak passphrases or low-entropy keys.
- Store salts and keys safely when deriving keys from passphrases.

### File and Stream Encryption

File and stream APIs use a versioned AES-GCM record format.

Properties:

- Per-record confidentiality, integrity, and authentication.
- Bounded memory during decryption.
- Version and algorithm validation before record processing.
- Rejection of truncated records and oversized record lengths.

Caller responsibilities:

- Treat any authentication failure as fatal.
- Choose chunk sizes appropriate for the application.
- Re-encrypt legacy pre-0.3 data with the current APIs.

### Key Management

`KeyStore` defines versioned key storage behavior. `MemoryKeyStore` is a dependency-free implementation for tests, local development, and small deployments.

Properties:

- Versioned lookup for decrypting older data.
- Current-key lookup for new encryption.
- Context-aware rotation and retrieval.
- Defensive copying of key bytes in the memory implementation.

Caller responsibilities:

- Protect any persistent key store.
- Rotate keys according to application risk and policy.
- Keep old key versions available until all data encrypted with them is migrated or expired.

### Envelope Wrapping

`KeyWrapper` defines data-key wrapping for local wrappers, OpenBao/Vault transit, and KMS adapters.

Properties:

- Wrapped keys should not expose plaintext key material.
- Authentication failures should be returned as errors.
- Provider SDK dependencies stay outside the core package.

Caller responsibilities:

- Configure KMS/secret-manager authorization outside fcrypt.
- Protect wrapping keys and KMS credentials.
- Include stable associated data when the backend supports it.

## Non-Goals

fcrypt does not provide:

- Application-level authorization or authentication.
- Secure deletion of plaintext or key material from memory.
- Protection after process, host, KMS, or secret-manager compromise.
- Password policy enforcement.
- A general-purpose cryptographic toolbox.
- Full KMS clients in the core module.

## Legacy Formats

fcrypt can read selected pre-0.3 formats for migration:

- Headerless AES-GCM file records.
- AES-CTR streams.

Legacy AES-CTR streams do not provide authentication or integrity. They are supported only to let users decrypt and re-encrypt data with the current authenticated stream format.
