package fcrypt

import "errors"

// Error variables
var (
	ErrCiphertextTooShort   = errors.New("ciphertext too short")
	ErrKeyLengthTooShort    = errors.New("key length too short")
	ErrFailedToCreateCipher = errors.New("failed to create new cipher")
	ErrFailedToCreateGCM    = errors.New("failed to create new GCM")
	ErrFailedToCreateFile   = errors.New("failed to create file")
	ErrFailedToReadData     = errors.New("failed to read data")
	ErrAuthenticationFailed = errors.New("authentication failed: ciphertext may be corrupt or tampered")
	ErrChunkSizeTooSmall    = errors.New("chunk size must be greater than 0")
	ErrInvalidFileFormat    = errors.New("invalid fcrypt file format")
	ErrUnsupportedVersion   = errors.New("unsupported fcrypt format version")
	ErrUnsupportedAlgorithm = errors.New("unsupported encryption algorithm")
	ErrInvalidRecordLength  = errors.New("invalid ciphertext record length")
	ErrTruncatedRecord      = errors.New("truncated ciphertext record")
	ErrUnsupportedHash      = errors.New("unsupported hash algorithm")
)
