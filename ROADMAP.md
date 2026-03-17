# Roadmap

Fcrypt’s roadmap focuses on (1) a stable, well-documented public API, (2) safe-by-default cryptography, and (3) compatibility/versioning guarantees for encrypted artifacts.

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
   - **Status**: Planning.

2. **Versioned file/container format**
   - **Goal**: Officially define the encrypted file record/container format, including framing and metadata.
   - **Details**:
     - Add a small header (magic + version + algorithm IDs + nonce size) so formats are self-describing.
     - Provide compatibility for older “nonce||ciphertext” layouts if they ever shipped.
   - **Status**: In progress.

3. **Hash algorithm selection API**
   - **Goal**: Let callers choose SHA-3, SHA-256, or SHA-512 without having to wire hashers manually.
   - **Details**:
     - Introduce a small enum-like type (e.g., `HashAlgorithm`) and `NewHasher(algo)`.
     - Keep the existing `Hash*(..., hash.Hash)` helpers for advanced users.
   - **Status**: Planned.

4. **Stream encryption: define correctness + security guarantees**
   - **Goal**: Decide whether streaming is authenticated by default.
   - **Details**:
     - Option A: chunked AEAD (recommended) with per-chunk nonce + length framing.
     - Option B: CTR + HMAC (only if explicitly requested; not default).
     - Document the security properties and expected use cases.
   - **Status**: Research/design.

## 0.4.0 — Key Management & Rotation API

1. **Key derivation and rotation policies**
   - **Goal**: Provide a structured way to define KDF parameters and rotation strategy.
   - **Details**:
     - Config struct for scrypt parameters (and potentially other KDFs in the future).
     - Rotation helpers that preserve metadata needed to decrypt older data.
   - **Status**: Conceptual.

2. **Key store abstraction**
   - **Goal**: Formalize a `KeyStore` interface for retrieving and storing versioned keys.
   - **Details**:
     - In-memory reference implementation.
     - Support for external backends in later milestones.
   - **Status**: Planned.

## 0.5.0 — Cloud Key Storage Integration (optional add-on)

1. **Cloud KMS integrations**
   - **Goal**: Optional integration with major cloud providers (AWS KMS, Google Cloud KMS, Azure Key Vault).
   - **Details**:
     - Keep provider SDKs out of the core module when possible (submodules or build tags).
     - Provide a consistent envelope-encryption workflow.
   - **Status**: Research and planning.

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
