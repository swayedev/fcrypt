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
)
