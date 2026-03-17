# fcrypt API

This document defines the intended public API for **fcrypt**, including stability goals, dependency policy, and security guarantees.

## Goals

- Make encryption **easy and ergonomic** for Go developers.
- Support **string/byte** encryption/decryption and **file** encryption/decryption.
- Support **key rotation** and re-encryption.
- Provide **hashing utilities**.
- Prefer **best-practice, highly secure algorithms and modes** to encourage correct defaults.
- Support large inputs efficiently via **streaming/chunked** processing.
- Avoid dependency overhead: prefer the Go standard library and only use **`golang.org/x/*`** when required.

## Non-goals

- General-purpose cryptographic toolbox.
- Supporting every key format or encryption mode.
- Providing a full key management service (KMS) client.

## Dependency policy

- **Standard library first**.
- **`golang.org/x/*` is allowed** when the standard library does not provide required primitives and the package is maintained by the Go team.
- Avoid third-party dependencies outside the Go standard library and `golang.org/x/*`.

## Stability policy

- fcrypt follows **SemVer**.
- Breaking changes to exported identifiers/behavior happen only in **major** versions.
- Encrypted file/container formats will be **versioned** and documented.

## Security model (high level)

- fcrypt intentionally supports a **small set** of algorithms/modes and prefers **secure-by-default** choices.
- Default encryption is **AEAD** using **AES-GCM**.
- Nonces are generated using `crypto/rand` and are unique per encrypted record.
- File encryption is chunked and **self-framed** in a record stream.

### Algorithm policy

- Only include algorithms/modes that are widely accepted as best practice.
- Avoid exposing insecure or foot-gun defaults.
- If an insecure/legacy mode is ever added for interoperability, it must be:
  - clearly named as such
  - documented with warnings
  - not the default

### Streaming and chunking

- “Streaming” in fcrypt means processing data incrementally in **bounded memory**.
- Large files are encrypted/decrypted as **records/chunks** rather than loading the entire payload into RAM.
- Chunk sizes should be user-configurable and have reasonable defaults.

### Concurrency and performance expectations

- APIs should be composable with goroutines and safe to use in concurrent workflows.
- Encryption/decryption should avoid unnecessary allocations and should not require loading full inputs into memory.
- File APIs should use framing so readers can process records sequentially.
- Where background goroutines are used (e.g., pipe-based streaming), they must:
  - propagate errors (`CloseWithError`)
  - not leak goroutines (ensure readers/writers are closed)

### Streaming

- Streaming APIs must clearly document whether they provide **authentication/integrity**.
- If an API is unauthenticated (e.g., CTR), it must be named/documented accordingly.

## Public API surface (intended)

The package aims to keep the stable public surface small and predictable.

## Context support

Some operations (especially file and streaming encryption) may run long enough that callers need cancellation/timeouts. For these cases, fcrypt should provide **context-aware variants**.

Conventions:

- Context-aware variants accept `ctx context.Context` as the first argument.
- If `ctx` is canceled, operations should return promptly with `ctx.Err()` or wrap it.
- For short/constant-time operations, context variants may be omitted.

Planned examples:

- `Encrypt(plaintext, key []byte) ([]byte, error)`
- `EncryptWithContext(ctx context.Context, plaintext, key []byte) ([]byte, error)`
- `EncryptFileToFile(...) error`
- `EncryptFileToFileWithContext(ctx context.Context, ...) error`

### Bytes

- `Encrypt(plaintext, key []byte) ([]byte, error)`
- `Decrypt(ciphertext, key []byte) ([]byte, error)`
- `ReEncrypt(ciphertext, oldKey, newKey []byte) ([]byte, error)`

**Encoding contract** (bytes): `nonce || ciphertext` where `nonce` is `gcm.NonceSize()`.

### Files

- `EncryptFileToFile(r io.Reader, key []byte, chunkSize int, outPath string) error`
- `DecryptFileToFile(inPath, outPath string, key []byte, chunkSize int) error`
- `ReEncryptFileToFile(inPath, outPath string, oldKey, newKey []byte, chunkSize int) error`

**Record contract** (files): repeated records of:

- `nonce || uint32(ciphertextLen) || ciphertext`

Notes:

- Records are self-framing.
- `chunkSize` controls plaintext read size; the file format itself is record-oriented.
- AEAD authentication happens per-record; callers should treat any authentication failure as fatal.

### Hashing

Two layers are supported:

1. **Generic helpers** (advanced / flexible)
   - `Hash(reader io.Reader, hasher hash.Hash) ([]byte, error)`
   - `HashBytes(data []byte, hasher hash.Hash) []byte`
   - `HashString(data string, hasher hash.Hash) []byte`
   - `HashFile(file *os.File, hasher hash.Hash) ([]byte, error)`

2. **Convenience helpers** (simple / batteries included)
   - SHA-256
     - `HashBytesSHA256`, `HashBytesToStringSHA256`, `HashStringSHA256`, `HashStringToStringSHA256`, `HashFileSHA256`
   - SHA-512
     - `HashBytesSHA512`, `HashBytesToStringSHA512`, `HashStringSHA512`, `HashStringToStringSHA512`, `HashFileSHA512`
   - SHA3-256 (via `golang.org/x/crypto/sha3`)
     - `HashBytesSHA3`, `HashBytesToStringSHA3`, `HashStringSHA3`, `HashStringToStringSHA3`, `HashFileSHA3`
   - BLAKE2b (via `golang.org/x/crypto/blake2b`)
     - `HashWithBlake2b256`, `HashWithBlake2b256NoKey`
     - `HashWithBlake2b512`, `HashWithBlake2b512NoKey`

### Key rotation

Key rotation is supported at the API level (key versioning + re-encryption) and is intended to remain simple:

- A `Key` interface to represent versioned keys.
- Rotation helpers that create new keys and allow re-encrypting existing ciphertext.

(Exact KeyStore abstractions and rotation policy configuration are tracked in `ROADMAP.md`.)

## Conventions

- Functions should accept raw `[]byte` keys to keep the API composable.
- Any function that outputs an encrypted format must document the on-disk/on-wire encoding.
- Crypto functions must keep their documentation aligned with the actual mode used.

## Planned additions (non-breaking)

- Hash selection enum:
  - `type HashAlgorithm ...`
  - `NewHasher(algo)` and `NewHash(algo)` helpers.
- File format header (magic + version + algorithm id) to make encrypted files self-describing.
- Authenticated streaming format (chunked AEAD) with explicit versioning.
