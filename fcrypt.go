package fcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	DefaultKeyLength      = 32
	ScryptN               = 32768
	ScryptR               = 8
	ScryptP               = 1
	MinNonceSize          = 12
	ErrCiphertextTooShort = "ciphertext too short"
)

// Key interface to provide methods for handling encryption keys
type Key interface {
	Version() string
	Salt() []byte
	Algo() string
	KeyBytes() []byte
}

// ScryptKey struct implements the Key interface
type ScryptKey struct {
	version string
	salt    []byte
	algo    string
	key     []byte
}

func (k *ScryptKey) Version() string {
	return k.version
}

func (k *ScryptKey) Salt() []byte {
	return k.salt
}

func (k *ScryptKey) Algo() string {
	return k.algo
}

func (k *ScryptKey) KeyBytes() []byte {
	return k.key
}

// Encrypt encrypts the given data using the provided key and returns the encrypted result.
// It uses the GCM mode of operation for encryption.
// The nonce is randomly generated and prepended to the encrypted data.
func Encrypt(data []byte, key []byte) ([]byte, error) {
	gcm, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts the given ciphertext using the provided key.
// It returns the plaintext or an error if decryption fails.
func Decrypt(data []byte, key []byte) ([]byte, error) {
	gcm, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ReEncrypt re-encrypts the given data using the oldKey and then encrypts it again using the newKey.
// It returns the re-encrypted data or an error if the encryption process fails.
func ReEncrypt(data []byte, oldKey []byte, newKey []byte) ([]byte, error) {
	decryptedData, err := Decrypt(data, oldKey)
	if err != nil {
		return nil, err
	}

	return Encrypt(decryptedData, newKey)
}

// StreamEncrypt takes an input data stream and a key, and returns an encrypted data stream along with any error encountered.
// The function generates a GCM (Galois/Counter Mode) cipher using the provided key, and then generates a random nonce.
// It uses the GCM cipher in CTR (Counter) mode to create a cipher stream reader, which encrypts the input data stream.
// The encrypted data stream is returned along with a possible error.
func StreamEncrypt(data io.Reader, key []byte) (io.Reader, error) {
	gcm, block, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	return cipher.StreamReader{
		S: cipher.NewCTR(block, nonce),
		R: data,
	}, nil
}

// StreamDecrypt decrypts the data from the given io.Reader using the provided key.
// It returns an io.Reader that can be used to read the decrypted data, along with any error encountered.
// The decryption is performed using the AES-GCM mode of operation.
// The key parameter is the secret key used for decryption.
// The data parameter is the encrypted data that needs to be decrypted.
// The returned io.Reader can be used to read the decrypted data.
// If an error occurs during decryption, it is returned along with a nil io.Reader.
func StreamDecrypt(data io.Reader, key []byte) (io.Reader, error) {
	gcm, block, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(data, nonce); err != nil {
		return nil, err
	}

	return cipher.StreamReader{
		S: cipher.NewCTR(block, nonce),
		R: data,
	}, nil
}

// StreamReEncrypt re-encrypts the data from the given reader using the oldKey and then encrypts it again using the newKey.
// It returns an io.Reader containing the re-encrypted data.
// If any error occurs during the decryption or encryption process, it returns nil and the error.
func StreamReEncrypt(data io.Reader, oldKey []byte, newKey []byte) (io.Reader, error) {
	decryptedStream, err := StreamDecrypt(data, oldKey)
	if err != nil {
		return nil, err
	}

	return StreamEncrypt(decryptedStream, newKey)
}

// GenerateSalt generates a random salt of the specified length.
// It uses the crypto/rand package to generate cryptographically secure random bytes.
// The length parameter specifies the number of bytes to generate.
// It returns the generated salt as a byte slice and any error encountered during the generation process.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateKey generates a key using the provided passphrase, salt, and key length.
// It uses the scrypt key derivation function to derive the key from the passphrase and salt.
// The key length specifies the desired length of the generated key in bytes.
// Returns the generated key as a byte slice and any error encountered during the key generation process.
func GenerateKey(passphrase string, salt []byte, keyLength int) ([]byte, error) {
	keyBytes, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keyLength)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// GenerateGCM generates a Galois/Counter Mode (GCM) cipher.AEAD and cipher.Block using the provided key.
// It returns the generated gcm, block, and any error encountered during the process.
func GenerateGCM(key []byte) (gcm cipher.AEAD, block cipher.Block, err error) {
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return gcm, block, nil
}

// Hashing functions
// HashStringToString takes a string as input and returns its SHA3-256 hash as a hexadecimal string.
func HashStringToString(data string) string {
	hashArray := sha3.Sum256([]byte(data))
	return hex.EncodeToString(hashArray[:])
}

// HashString calculates the SHA3-256 hash of the input string.
// It takes a string as input and returns a fixed-size array of 32 bytes.
func HashString(data string) [32]byte {
	return sha3.Sum256([]byte(data))
}

// HashByte calculates the SHA3-256 hash of the given byte slice.
// It returns a fixed-size array of 32 bytes representing the hash.
func HashByte(data []byte) [32]byte {
	return sha3.Sum256([]byte(data))
}
