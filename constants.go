package fcrypt

// Constants
const (
	// MinKeyLength is the minimum length of the encryption key in bytes.
	MinKeyLength = 16
	// DefaultKeyLength is the default length of the encryption key in bytes.
	DefaultKeyLength = 32

	// ScryptN is the CPU/memory cost parameter for scrypt.
	ScryptN = 32768
	// ScryptR is the block size parameter for scrypt.
	ScryptR = 8
	// ScryptP is the parallelization parameter for scrypt.
	ScryptP = 1

	// MinNonceSize is the minimum size of the nonce in bytes.
	MinNonceSize = 12
	// GCMNonceSize is the size of the nonce used in GCM mode.
	GCMNonceSize = 12

	// DefaultChunkSize is the default plaintext record size for framed APIs.
	DefaultChunkSize = 64 * 1024
	// MaxCiphertextRecordSize is the largest ciphertext record accepted by framed decryptors.
	MaxCiphertextRecordSize = 64 * 1024 * 1024
)
