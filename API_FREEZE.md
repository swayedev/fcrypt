# fcrypt v1 API Freeze Checklist

The following public API names are accepted for `v1.0.0-rc1`.

## Core Encryption

- `Encrypt`
- `Decrypt`
- `ReEncrypt`
- `EncryptWithContext`
- `DecryptWithContext`
- `ReEncryptWithContext`
- `GenerateGCM`
- `GenerateGCMWithNonce`

## File and Stream Encryption

- `EncryptFileToFile`
- `EncryptFileToFileWithContext`
- `DecryptFileToFile`
- `DecryptFileToFileWithContext`
- `ReEncryptFileToFile`
- `ReEncryptFileToFileWithContext`
- `StreamEncrypt`
- `StreamDecrypt`
- `StreamReEncrypt`
- `LegacyEncryptFileToFile`
- `LegacyStreamEncrypt`
- `LegacyStreamDecrypt`

The `Legacy*` names are intentionally explicit and should remain migration-only APIs.

## Key Derivation and Rotation

- `GenerateSalt`
- `GenerateKey`
- `GenerateKeyWithConfig`
- `GenerateSaltAndKey`
- `KDFConfig`
- `DefaultKDFConfig`
- `Key`
- `FcryptKey`
- `NewFcryptKey`
- `RotationPolicy`
- `KeyStore`
- `MemoryKeyStore`
- `NewMemoryKeyStore`
- `RotateKey`
- `RotateKeyWithContext`

`RotateKey` remains for compatibility with the pre-0.4 `map[string]Key` API. New code should prefer `KeyStore`.

## Envelope Wrapping

- `WrapOptions`
- `WrappedKey`
- `KeyWrapper`
- `LocalKeyWrapper`
- `NewLocalKeyWrapper`

## Hashing

- `HashAlgorithm`
- `HashAlgorithmSHA256`
- `HashAlgorithmSHA512`
- `HashAlgorithmSHA3_256`
- `HashAlgorithmBLAKE2b256`
- `HashAlgorithmBLAKE2b512`
- `NewHasher`
- `NewHash`
- Generic and convenience `Hash*` helpers documented in `API.md`.

## Keys Subpackage

New code should import `github.com/swayedev/fcrypt/keys` for key parsing and generation.

The root package keeps compatibility wrappers for existing users.

## Adapter Packages

- `github.com/swayedev/fcrypt/adapters/memory`
- `github.com/swayedev/fcrypt/adapters/openbao`
- `github.com/swayedev/fcrypt/adapters/vault`
- `github.com/swayedev/fcrypt/adapters/awskms`
- `github.com/swayedev/fcrypt/adapters/gcpkms`
- `github.com/swayedev/fcrypt/adapters/azurekeyvault`

Cloud KMS adapters are intentionally SDK-neutral and accept caller-supplied minimal client interfaces.

## Deferred Beyond v1.0.0

- Full provider SDK clients in the core module.
- secp256k1 support in core.
- Secure memory wiping.
- General-purpose cryptographic primitive expansion.
