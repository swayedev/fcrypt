package fcrypt

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// HashAlgorithm identifies a supported convenience hash algorithm.
type HashAlgorithm string

const (
	HashAlgorithmSHA256     HashAlgorithm = "SHA-256"
	HashAlgorithmSHA512     HashAlgorithm = "SHA-512"
	HashAlgorithmSHA3_256   HashAlgorithm = "SHA3-256"
	HashAlgorithmBLAKE2b256 HashAlgorithm = "BLAKE2b-256"
	HashAlgorithmBLAKE2b512 HashAlgorithm = "BLAKE2b-512"
)

// NewHasher returns a new hash.Hash for the requested algorithm.
func NewHasher(algo HashAlgorithm) (hash.Hash, error) {
	switch algo {
	case HashAlgorithmSHA256:
		return sha256.New(), nil
	case HashAlgorithmSHA512:
		return sha512.New(), nil
	case HashAlgorithmSHA3_256:
		return sha3.New256(), nil
	case HashAlgorithmBLAKE2b256:
		return blake2b.New256(nil)
	case HashAlgorithmBLAKE2b512:
		return blake2b.New512(nil)
	default:
		return nil, ErrUnsupportedHash
	}
}

// NewHash is an alias for NewHasher.
func NewHash(algo HashAlgorithm) (hash.Hash, error) {
	return NewHasher(algo)
}

// Hash calculates the hash of the given io.Reader using the provided hash.Hash.
func Hash(reader io.Reader, hasher hash.Hash) ([]byte, error) {
	if _, err := io.Copy(hasher, reader); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// HashBytes calculates the hash of the given byte slice using the provided hash.Hash.
func HashBytes(data []byte, hasher hash.Hash) []byte {
	hasher.Write(data)
	return hasher.Sum(nil)
}

// HashBytesToString calculates the hash of the given byte slice using the provided hash.Hash.
func HashBytesToString(data []byte, hasher hash.Hash) string {
	return hex.EncodeToString(HashBytes(data, hasher))
}

// HashString calculates the hash of the given string using the provided hash.Hash.
func HashString(data string, hasher hash.Hash) []byte {
	hasher.Write([]byte(data))
	return hasher.Sum(nil)
}

// HashStringToString calculates the hash of the given string using the provided hash.Hash.
func HashStringToString(data string, hasher hash.Hash) string {
	return hex.EncodeToString(HashString(data, hasher))
}

// HashFile calculates the hash of the given file using the provided hash.Hash.
func HashFile(file *os.File, hasher hash.Hash) ([]byte, error) {
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// SHA-256 helpers

func HashBytesSHA256(data []byte) []byte { return HashBytes(data, sha256.New()) }
func HashBytesToStringSHA256(data []byte) string {
	return hex.EncodeToString(HashBytes(data, sha256.New()))
}
func HashStringSHA256(data string) []byte          { return HashString(data, sha256.New()) }
func HashStringToStringSHA256(data string) string  { return HashStringToString(data, sha256.New()) }
func HashFileSHA256(file *os.File) ([]byte, error) { return HashFile(file, sha256.New()) }

// SHA-512 helpers

func HashBytesSHA512(data []byte) []byte { return HashBytes(data, sha512.New()) }
func HashBytesToStringSHA512(data []byte) string {
	return hex.EncodeToString(HashBytes(data, sha512.New()))
}
func HashStringSHA512(data string) []byte          { return HashString(data, sha512.New()) }
func HashStringToStringSHA512(data string) string  { return HashStringToString(data, sha512.New()) }
func HashFileSHA512(file *os.File) ([]byte, error) { return HashFile(file, sha512.New()) }

// SHA3-256 helpers

func HashBytesSHA3(data []byte) []byte { return HashBytes(data, sha3.New256()) }
func HashBytesToStringSHA3(data []byte) string {
	return hex.EncodeToString(HashBytes(data, sha3.New256()))
}
func HashStringSHA3(data string) []byte          { return HashString(data, sha3.New256()) }
func HashStringToStringSHA3(data string) string  { return HashStringToString(data, sha3.New256()) }
func HashFileSHA3(file *os.File) ([]byte, error) { return HashFile(file, sha3.New256()) }

// BLAKE2b helpers

func HashWithBlake2b512(reader io.Reader, key []byte) ([]byte, error) {
	hasher, err := blake2b.New512(key)
	if err != nil {
		return nil, err
	}
	return Hash(reader, hasher)
}

func HashWithBlake2b512NoKey(reader io.Reader) ([]byte, error) {
	return HashWithBlake2b512(reader, nil)
}

func HashWithBlake2b256(reader io.Reader, key []byte) ([]byte, error) {
	hasher, err := blake2b.New256(key)
	if err != nil {
		return nil, err
	}
	return Hash(reader, hasher)
}

func HashWithBlake2b256NoKey(reader io.Reader) ([]byte, error) {
	return HashWithBlake2b256(reader, nil)
}
