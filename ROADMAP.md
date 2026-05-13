# Roadmap

Fcrypt’s roadmap focuses on (1) a stable, well-documented public API, (2) safe-by-default cryptography, and (3) compatibility/versioning guarantees for encrypted artifacts.

## Production readiness plan

Before fcrypt is presented as production-ready, it should satisfy these release gates:

1. **Secure-by-default encryption**
   - Authenticated encryption must be the default for bytes, files, and streaming.
   - Existing AES-CTR streaming APIs have been replaced by authenticated chunked AEAD APIs in 0.3.0.
   - Malformed ciphertext, truncated files, huge length headers, wrong keys, and invalid key sizes must return errors without panics or unbounded memory allocation.

2. **Versioned formats and compatibility**
   - File/container formats must include a small header with magic, format version, algorithm, nonce size, and record framing metadata.
   - Decryption must have a documented compatibility story for older formats.
   - Every serialized format must have golden tests.

3. **Key management that composes with secret managers**
   - Core fcrypt should define small interfaces for versioned key storage and envelope encryption.
   - Core fcrypt should ship an in-memory implementation for tests and local use.
   - Secret-manager support should live in optional adapter packages so the core module stays dependency-light.

4. **Operational safety**
   - All long-running file/stream operations should have context-aware variants.
   - APIs should avoid logging secrets, derived keys, raw salts, plaintext, or ciphertext.
   - Sensitive examples should show realistic key handling rather than hard-coded production keys.

5. **Documentation and review**
   - Publish an API stability policy, threat model, and security property matrix.
   - Document what fcrypt does not protect against.
   - Complete an internal security review before v1.0.0 and leave space for an external review before broad public adoption.

## Dependency policy

- **Standard library first** for all core encryption and file APIs.
- **`golang.org/x/*` allowed when required** (extended Go libraries maintained by the Go team).
- Avoid third-party dependencies outside of the Go standard library and `golang.org/x/*`.

## Compatibility and API Stability

- **Public API stability**: breaking changes will be limited to major releases (v1.0.0, v2.0.0, …). Minor/patch releases will remain source-compatible.
- **Encrypted data format stability**: all on-disk formats will be versioned. New formats will remain readable by newer versions; decryption of legacy formats will remain supported for a defined window.
- **Semantic versioning (SemVer)**: the library will follow SemVer for exported identifiers and behavior.

## 0.3.0 — Solidify the Core API (near-term)

1. **Stable API surface**
   - **Goal**: Define and document the “core” package API that will remain stable across 0.x and into 1.0.
   - **Details**:
     - Clear separation between:
       - *high-level convenience APIs* (simple Encrypt/Decrypt)
       - *streaming APIs* (io.Reader/io.Writer)
       - *file/container APIs* (versioned file format)
     - Consistent naming for algorithms and modes.
   - **Status**: Complete for 0.3.0.

2. **Versioned file/container format**
   - **Goal**: Officially define the encrypted file record/container format, including framing and metadata.
   - **Details**:
     - Add a small header (magic + version + algorithm IDs + nonce size) so formats are self-describing.
     - Provide compatibility for older “nonce||ciphertext” layouts if they ever shipped.
   - **Status**: Complete for 0.3+. Decryptors can read the older headerless file record format for migration.

3. **Hash algorithm selection API**
   - **Goal**: Let callers choose SHA-3, SHA-256, or SHA-512 without having to wire hashers manually.
   - **Details**:
     - Introduce a small enum-like type (e.g., `HashAlgorithm`) and `NewHasher(algo)`.
     - Keep the existing `Hash*(..., hash.Hash)` helpers for advanced users.
   - **Status**: Complete for 0.3.0.

4. **Stream encryption: define correctness + security guarantees**
   - **Goal**: Decide whether streaming is authenticated by default.
   - **Details**:
     - Option A: chunked AEAD (recommended) with per-chunk nonce + length framing.
     - Option B: CTR + HMAC (only if explicitly requested; not default).
     - Document the security properties and expected use cases.
   - **Status**: Complete for 0.3+. Streaming now uses authenticated AES-GCM records by default, and `StreamDecrypt` can read pre-0.3 AES-CTR streams for migration.

5. **Malformed input hardening**
   - **Goal**: Make decrypt/re-encrypt safe against hostile or corrupted input.
   - **Details**:
     - Enforce maximum ciphertext record sizes.
     - Validate file headers before allocating record buffers.
     - Return typed errors for truncated records, unsupported versions, invalid algorithms, and authentication failures.
     - Add tests for corrupted files, massive length headers, wrong keys, empty files, and partial records.
   - **Status**: Complete for 0.3.0.

## 0.4.0 — Key Management & Rotation API

1. **Key derivation and rotation policies**
   - **Goal**: Provide a structured way to define KDF parameters and rotation strategy.
   - **Details**:
     - Config struct for scrypt parameters (and potentially other KDFs in the future).
     - Rotation helpers that preserve metadata needed to decrypt older data.
   - **Status**: Complete for 0.4.0.

2. **Key store abstraction**
   - **Goal**: Formalize a `KeyStore` interface for retrieving and storing versioned keys.
   - **Details**:
     - In-memory reference implementation.
     - Context-aware methods.
     - Current-key lookup for new encryption.
     - Versioned-key lookup for decryption of existing data.
     - Atomic rotation semantics where a backend supports them.
     - Support for external backends through optional adapters.
   - **Status**: Complete for 0.4.0.

3. **Envelope encryption API**
   - **Goal**: Support secret managers and KMS systems without requiring them to store every data-encryption key in plaintext.
   - **Details**:
     - Generate local data-encryption keys with `crypto/rand`.
     - Wrap/unwrap data keys through an adapter-backed key-encryption key.
     - Store metadata needed to locate the wrapping key version.
     - Keep envelope metadata versioned and serializable.
   - **Status**: Complete for 0.4.0.

4. **Reference interfaces**
   - **Goal**: Keep adapter contracts small enough for OpenBao, Vault, cloud KMS, and local stores.
   - **Interfaces**:

   ```go
   type KeyStore interface {
      Put(ctx context.Context, key Key) error
      Get(ctx context.Context, version string) (Key, error)
      Current(ctx context.Context) (Key, error)
      Rotate(ctx context.Context, policy RotationPolicy) (Key, error)
   }

   type KeyWrapper interface {
      WrapKey(ctx context.Context, plaintextKey []byte, opts WrapOptions) (WrappedKey, error)
      UnwrapKey(ctx context.Context, wrapped WrappedKey) ([]byte, error)
   }
   ```

   - **Status**: Complete for 0.4.0.

## 0.5.0 — Secret Manager and KMS Adapters

Adapters should be optional packages. They should not add dependencies to the core `github.com/swayedev/fcrypt` module unless the user imports the adapter.

Proposed package layout:

- `github.com/swayedev/fcrypt/adapters/memory`
- `github.com/swayedev/fcrypt/adapters/openbao`
- `github.com/swayedev/fcrypt/adapters/vault`
- `github.com/swayedev/fcrypt/adapters/awskms`
- `github.com/swayedev/fcrypt/adapters/gcpkms`
- `github.com/swayedev/fcrypt/adapters/azurekeyvault`

The core package already includes `MemoryKeyStore` and `LocalKeyWrapper` as dependency-free reference implementations. The `adapters/memory` package exposes those implementations through the same adapter-shaped import path users can use for external backends.

1. **Memory adapter**
   - **Goal**: Support users who do not have OpenBao, Vault, or a cloud KMS.
   - **Details**:
     - Re-export the core `MemoryKeyStore` and `LocalKeyWrapper`.
     - Keep the package dependency-free.
     - Useful for tests, small deployments, local development, and users who want a consistent adapter import path before moving to an external backend.
   - **Status**: Complete.

2. **OpenBao adapter**
   - **Goal**: Support OpenBao-backed key storage and envelope encryption.
   - **Details**:
     - Prefer OpenBao transit-style wrapping when available.
     - Store fcrypt key metadata in a stable path layout.
     - Support explicit mount/path configuration.
     - Keep OpenBao client dependencies isolated to the adapter package.
     - Add integration tests that can run against a local OpenBao dev container.
   - **Status**: Complete for 0.5.0.

3. **Vault-compatible adapter**
   - **Goal**: Support HashiCorp Vault or Vault-compatible deployments where needed.
   - **Details**:
     - Keep separate from OpenBao if client libraries or auth flows diverge.
     - Prefer the same `KeyStore`/`KeyWrapper` contract.
   - **Status**: Complete for 0.5.0.

4. **Cloud KMS integrations**
   - **Goal**: Optional integration with major cloud providers.
   - **Details**:
     - AWS KMS.
     - Google Cloud KMS.
     - Azure Key Vault.
     - Keep provider SDKs out of the core module when possible (submodules or build tags).
     - Provide a consistent envelope-encryption workflow.
   - **Status**: Complete for 0.5.0 as SDK-neutral adapters around caller-supplied clients.

5. **Adapter acceptance criteria**
   - **Goal**: Make adapters reliable enough for production use.
   - **Details**:
     - Unit tests with mocked backends.
     - Integration tests gated behind environment variables.
     - Timeout/cancellation support through `context.Context`.
     - Clear auth/config documentation.
     - No secret values in logs or error strings.
     - Stable error wrapping so callers can distinguish missing keys, permission failures, backend unavailability, and unwrap/authentication failures.
   - **Status**: Complete for 0.5.0.

## 0.6.0 — Extended Elliptic Curve & Interop

1. **Extended elliptic curve support**
   - **Goal**: Support additional curves where it improves interoperability.
   - **Details**:
     - Evaluate secp256k1 and any required third-party dependencies.
     - Ensure key parsing/encoding remains explicit and test-backed.
   - **Status**: In development.

## 1.0.0 — “Stable by Default” Release

- **Goal**: Lock in stable APIs, stable format(s), and well-tested security guarantees.
- **Requirements**:
  - Documented threat model and security properties.
  - Backwards compatibility story for file/container formats.
  - Comprehensive tests across chunking boundaries, large files, and key types.
  - Clear migration guidance for any pre-1.0 format/API changes.
  - Authenticated streaming.
  - `KeyStore` and `KeyWrapper` interfaces stabilized.
  - At least one production-grade secret manager adapter, preferably OpenBao, available outside the core module.
  - Fuzz tests for parsers/decryptors and malformed encrypted files.
