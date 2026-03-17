package fcrypt

// Package fcrypt provides ergonomic helpers for encrypting/decrypting bytes and files,
// key derivation/rotation, and hashing utilities.
//
// Implementation is split across multiple files:
// - crypto.go: AES-GCM helpers and byte-slice Encrypt/Decrypt APIs
// - file.go: chunked file encryption using a framed record stream
// - stream.go: streaming APIs
// - kdf.go: key derivation helpers
// - hash.go: hashing helpers
// - parser.go / generate.go: key parsing and generation
// - types.go / constants.go / errors.go: shared types/constants/errors
