package fcrypt

// Key interface to provide methods for handling encryption keys.
type Key interface {
	// Encryption key version
	Version() string
	// Salt used for key derivation
	Salt() []byte
	// Encryption algorithm
	Algo() string
	// Encryption key as byte slice
	KeyBytes() []byte
}

// FcryptKey struct implements the Key interface.
type FcryptKey struct {
	version string
	salt    []byte
	algo    string
	key     []byte
}

// SetVersion sets the version of the FcryptKey.
func (k *FcryptKey) SetVersion(v string) {
	k.version = v
}

// Version returns the version of the FcryptKey.
func (k *FcryptKey) Version() string {
	return k.version
}

// SetSalt sets the salt value for the FcryptKey.
// The salt is used as an additional input to the key derivation function,
// making it harder to perform precomputed dictionary attacks.
func (k *FcryptKey) SetSalt(s []byte) {
	k.salt = cloneBytes(s)
}

// Salt returns the salt value associated with the FcryptKey.
func (k *FcryptKey) Salt() []byte {
	return cloneBytes(k.salt)
}

// SetAlgo sets the encryption algorithm for the FcryptKey.
// The algorithm should be a string representing the desired encryption algorithm.
func (k *FcryptKey) SetAlgo(a string) {
	k.algo = a
}

// Algo returns the algorithm used by the FcryptKey.
func (k *FcryptKey) Algo() string {
	return k.algo
}

// SetKeyBytes sets the key bytes for the FcryptKey instance.
// The key parameter is a byte slice containing the key bytes.
func (k *FcryptKey) SetKeyBytes(key []byte) {
	k.key = cloneBytes(key)
}

// KeyBytes returns the key bytes of the FcryptKey.
func (k *FcryptKey) KeyBytes() []byte {
	return cloneBytes(k.key)
}

// SetAll sets the values of the FcryptKey struct.
// It takes in the version string, salt byte slice, algorithm string, and key byte slice as parameters.
func (k *FcryptKey) SetAll(v string, s []byte, a string, key []byte) {
	k.version = v
	k.salt = cloneBytes(s)
	k.algo = a
	k.key = cloneBytes(key)
}

// NewFcryptKey creates a new FcryptKey with the specified version, salt, algorithm, and key.
func NewFcryptKey(version string, salt []byte, algo string, key []byte) *FcryptKey {
	return &FcryptKey{
		version: version,
		salt:    cloneBytes(salt),
		algo:    algo,
		key:     cloneBytes(key),
	}
}
