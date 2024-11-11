# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added function `GenerateSaltAndKey` combining `GenerateSalt` and `GenerateKey` functions into one

## [0.2.2] - 2024-11-10

- Security patch: Updated dependencies

## [0.2.1] - 2024-08-02

### Added

- Added functions to enable use of default `FcryptKey`

## [0.2.0] - 2024-08-02

### Added

- Added `ReEncryptFileToFile` for re-encrypting files with a new key.
- Added `GenerateGCMWithNonce` for generating a GCM cipher with a random nonce.
- Added versatility to hashing functions by allowing the use of different hashing algorithms via the generalized `Hash` function.
- Added `HashFile` for generating file hashes.
- Added specific hashing functions for SHA3-256: `HashBytesSHA3`, `HashBytesToStringSHA3`, `HashStringSHA3`, `HashStringToStringSHA3`, and `HashFileSHA3`.
- Added specific hashing functions for BLAKE2b: `HashWithBlake2b512`, `HashWithBlake2b512NoKey`, `HashWithBlake2b256`, and `HashWithBlake2b256NoKey`.

### Changed

- Renamed `HashByte` function to `HashBytes`
- Consolidated hashing functions to accept a `hash.Hash` parameter, making the API more flexible and versatile.
- Generalized `Hash` function for hashing `io.Reader` data using a provided `hash.Hash`.

### Fixed

- Fixed `StreamEncrypt` and `StreamDecrypt` CipherIV issues.

## [0.1.0] - 2024-07-31

### Added

- Initial release of Fcrypt.
- Basic encryption and decryption functions using AES-GCM.
- Stream encryption and decryption support.
- Encrypt large data and files in chunks.
- Key rotation and re-encryption support.
- Extensible key management with an interface for different key types.
- Hashing functions using SHA3-256.
- Comprehensive README with usage examples.
