# Fcrypt

Fcrypt is a flexible and secure encryption package for Go, providing easy-to-use functions for encrypting and decrypting data using AES-GCM (Galois/Counter Mode). This package is designed for simplicity and security, making it suitable for various applications requiring data protection.

## Features

- Encrypt and decrypt data with AES-GCM.
- Stream encryption and decryption.
- Encrypt large data and files in chunks.
- Key rotation and re-encryption support.
- Extensible key management with an interface for different key types.
- Hashing functions using SHA3-256 and BLAKE2b.

## Installation

To install Fcrypt, use `go get`:

```bash
go get github.com/swayedev/fcrypt
```

## Usage

### Basic Encryption and Decryption

Here's how you can encrypt and decrypt data using Fcrypt:

```go
package main

import (
    "fmt"
    "log"

    "github.com/swayedev/fcrypt"
)

func main() {
    passphrase := "your-secure-passphrase"
    data := []byte("Sensitive data here")

    // Generate salt
    salt, err := fcrypt.GenerateSalt(16)
    if err != nil {
        log.Fatalf("Failed to generate salt: %v", err)
    }

    // Generate key
    key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    // Encrypt data
    encryptedData, err := fcrypt.Encrypt(data, key)
    if err != nil {
        log.Fatalf("Failed to encrypt data: %v", err)
    }

    // Decrypt data
    decryptedData, err := fcrypt.Decrypt(encryptedData, key)
    if err != nil {
        log.Fatalf("Failed to decrypt data: %v", err)
    }

    fmt.Printf("Original data: %s\n", data)
    fmt.Printf("Decrypted data: %s\n", decryptedData)
}
```

### Stream Encryption and Decryption

Fcrypt supports stream encryption and decryption for large data:

```go
package main

import (
    "bytes"
    "io"
    "log"
    "os"

    "github.com/swayedev/fcrypt"
)

func main() {
    passphrase := "your-secure-passphrase"

    // Generate salt
    salt, err := fcrypt.GenerateSalt(16)
    if err != nil {
        log.Fatalf("Failed to generate salt: %v", err)
    }

    // Generate key
    key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    // Open file to encrypt
    file, err := os.Open("largefile.txt")
    if err != nil {
        log.Fatalf("Failed to open file: %v", err)
    }
    defer file.Close()

    // Encrypt file stream
    encryptedStream, err := fcrypt.StreamEncrypt(file, key)
    if err != nil {
        log.Fatalf("Failed to encrypt file stream: %v", err)
    }

    // For demonstration, read the encrypted stream into a buffer
    encryptedData, err := io.ReadAll(encryptedStream)
    if err != nil {
        log.Fatalf("Failed to read encrypted stream: %v", err)
    }

    // Decrypt the encrypted stream
    decryptedStream, err := fcrypt.StreamDecrypt(bytes.NewReader(encryptedData), key)
    if err != nil {
        log.Fatalf("Failed to decrypt file stream: %v", err)
    }

    // Read the decrypted data from the stream
    decryptedData, err := io.ReadAll(decryptedStream)
    if err != nil {
        log.Fatalf("Failed to read decrypted stream: %v", err)
    }

    log.Printf("Decrypted data: %s", decryptedData)
}
```

### Encrypting and Decrypting Large Data Files

Fcrypt supports encrypting and decrypting large data files in chunks:

```go
package main

import (
    "log"
    "os"

    "github.com/swayedev/fcrypt"
)

func main() {
    passphrase := "your-secure-passphrase"

    // Generate salt
    salt, err := fcrypt.GenerateSalt(16)
    if err != nil {
        log.Fatalf("Failed to generate salt: %v", err)
    }

    // Generate key
    key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    // Open file to encrypt
    inputFile, err := os.Open("largefile.txt")
    if err != nil {
        log.Fatalf("Failed to open file: %v", err)
    }
    defer inputFile.Close()

    // Encrypt file
    if err := fcrypt.EncryptFileToFile(inputFile, key, 4096, "largefile.encrypted"); err != nil {
        log.Fatalf("Failed to encrypt file: %v", err)
    }

    // Decrypt file
    if err := fcrypt.DecryptFileToFile("largefile.encrypted", "largefile.decrypted", key, 4096); err != nil {
        log.Fatalf("Failed to decrypt file: %v", err)
    }
}
```

### Key Rotation and Re-Encryption

Fcrypt also supports key rotation and re-encryption:

```go
package main

import (
    "fmt"
    "log"

    "github.com/swayedev/fcrypt"
)

func main() {
    passphrase := "your-secure-passphrase"
    keyStore := make(map[string]fcrypt.Key)

    // Rotate key
    version, err := fcrypt.RotateKey(passphrase, keyStore, fcrypt.DefaultKeyLength)
    if err != nil {
        log.Fatalf("Failed to rotate key: %v", err)
    }

    oldKey := keyStore[version]

    data := []byte("Sensitive data here")

    // Encrypt data with the old key
    encryptedData, err := fcrypt.Encrypt(data, oldKey.KeyBytes())
    if err != nil {
        log.Fatalf("Failed to encrypt data: %v", err)
    }

    // Rotate key again
    newVersion, err := fcrypt.RotateKey(passphrase, keyStore, fcrypt.DefaultKeyLength)
    if err != nil {
        log.Fatalf("Failed to rotate key: %v", err)
    }

    newKey := keyStore[newVersion]

    // Re-encrypt data with the new key
    reEncryptedData, err := fcrypt.ReEncrypt(encryptedData, oldKey.KeyBytes(), newKey.KeyBytes())
    if err != nil {
        log.Fatalf("Failed to re-encrypt data: %v", err)
    }

    // Decrypt data with the new key
    decryptedData, err := fcrypt.Decrypt(reEncryptedData, newKey.KeyBytes())
    if err != nil {
        log.Fatalf("Failed to decrypt data: %v", err)
    }

    fmt.Printf("Original data: %s\n", data)
    fmt.Printf("Decrypted data: %s\n", decryptedData)
}
```

### Hashing Functions

Fcrypt includes hashing functions using SHA3-256 and BLAKE2b:

```go
package main

import (
    "fmt"
    "os"
    "strings"

    "github.com/swayedev/fcrypt"
)

func main() {
    data := "Sensitive data here"

    // Hash string to string using SHA3-256
    hashedStringSHA3 := fcrypt.HashStringToStringSHA3(data)
    fmt.Printf("SHA3-256 Hashed string: %s\n", hashedStringSHA3)

    // Hash string to byte array using SHA3-256
    hashedArraySHA3 := fcrypt.HashStringSHA3(data)
    fmt.Printf("SHA3-256 Hashed array: %x\n", hashedArraySHA3)

    // Hash byte slice using SHA3-256
    hashedBytesSHA3 := fcrypt.HashBytesSHA3([]byte(data))
    fmt.Printf("SHA3-256 Hashed bytes: %x\n", hashedBytesSHA3)

    // Hash file using SHA3-256
    file, err := os.Open("largefile.txt")
    if err != nil {
        fmt.Printf("Failed to open file: %v\n", err)
        return
    }
    defer file.Close()
    hashedFileSHA3, err := fcrypt.HashFileSHA3(file)
    if err != nil {
        fmt.Printf("Failed to hash file: %v\n", err)
        return
    }
    fmt.Printf("SHA3-256 Hashed file: %x\n", hashedFileSHA3)

    // Hash string to string using BLAKE2b-512
    reader := strings.NewReader(data)
    hashedStringBlake2b512, err := fcrypt.HashWithBlake2b512(reader, nil)
    if err != nil {
        fmt.Printf("Failed to hash string with BLAKE2b-512: %v\n", err)
        return
    }
    fmt.Printf("BLAKE2b-512 Hashed string: %x\n", hashedStringBlake2b512)
}
```

## API Reference

### Types

- `Key`: Interface for handling encryption keys.
- `FcryptKey`: Implementation of the `Key` interface using scrypt.

### Constants

- `MinKeyLength`: Minimum key length (16 bytes).
- `DefaultKeyLength`: Default length for keys (32 bytes).
- `ScryptN`, `ScryptR`, `ScryptP`: Parameters for the scrypt key derivation function.
- `MinNonceSize`: Minimum nonce size (12 bytes).
- `GCMNonceSize`: Size of the nonce used in GCM mode.

### Error Variables

- `ErrCiphertextTooShort`: Error message for short ciphertext.
- `ErrKeyLengthTooShort`: Error message for short key length.
- `ErrFailedToCreateCipher`: Error message for failing to create a cipher.
- `ErrFailedToCreateGCM`: Error message for failing to create GCM.
- `ErrFailedToCreateFile`: Error message for failing to create a file.
- `ErrFailedToReadData`: Error message for failing to read data.

### Functions

- `GenerateSalt(length int) ([]byte, error)`: Generates a random salt.
- `GenerateKey(passphrase string, salt []byte, keyLength int) ([]byte, error)`: Generates a key using scrypt.
- `GenerateGCM(key []byte) (cipher.AEAD, cipher.Block, error)`: Generates a GCM cipher.
- `GenerateGCMWithNonce(key []byte) (cipher.AEAD, cipher.Block, []byte, error)`: Generates a GCM cipher with a random nonce.
- `Encrypt(data []byte, key []byte) ([]byte, error)`: Encrypts data.
- `Decrypt(data []byte, key []byte) ([]byte, error)`: Decrypts data.
- `ReEncrypt(data []byte, oldKey []byte, newKey []byte) ([]byte, error)`: Re-encrypts data with a new key.
- `StreamEncrypt(data io.Reader, key []byte) (io.Reader, error)`: Encrypts data stream.
- `StreamDecrypt(data io.Reader, key []byte) (io.Reader, error)`: Decrypts data stream.
- `StreamReEncrypt(data io.Reader, oldKey []byte, newKey []byte) (io.Reader, error)`: Re-encrypts data stream with a new key.
- `EncryptFileToFile(data io.Reader, key []byte, chunkSize int, filePath string) error`: Encrypts data from a reader and writes it to a file.
- `DecryptFileToFile(encryptedFilePath, decryptedFilePath string, key []byte, chunkSize int) error`: Decrypts data from an encrypted file and writes it to a new file.
- `HashBytes(data []byte, hasher hash.Hash) []byte`: Hashes a byte slice.
- `HashBytesToString(data []byte, hasher hash.Hash) string`: Hashes a byte slice and returns a hexadecimal string.
- `HashString(data string, hasher hash.Hash) []byte`: Hashes a string.
- `HashStringToString(data string, hasher hash.Hash) string`: Hashes a string and returns a hexadecimal string.
- `HashFile(file *os.File, hasher hash.Hash) ([]byte, error)`: Hashes the contents of a file.
- `HashBytesSHA3(data []byte) []byte`: Hashes a byte slice using SHA3-256.
- `HashBytesToStringSHA3(data []byte) string`: Hashes a byte slice using SHA3-256 and returns a hexadecimal string.
- `HashStringSHA3(data string) []byte`: Hashes a string using SHA3-256.
- `HashStringToStringSHA3(data string) string`: Hashes a string using SHA3-256 and returns a hexadecimal string.
- `HashFileSHA3(file *os.File) ([]byte, error)`: Hashes the contents of a file using SHA3-256.
- `HashWithBlake2b512(reader io.Reader, key []byte) ([]byte, error)`: Hashes the contents of an `io.Reader` using BLAKE2b-512.
- `HashWithBlake2b512NoKey(reader io.Reader) ([]byte, error)`: Hashes the contents of an `io.Reader` using BLAKE2b-512 without a key.
- `HashWithBlake2b256(reader io.Reader, key []byte) ([]byte, error)`: Hashes the contents of an `io.Reader` using BLAKE2b-256.
- `HashWithBlake2b256NoKey(reader io.Reader) ([]byte, error)`: Hashes the contents of an `io.Reader` using BLAKE2b-256 without a key.
- `RotateKey(passphrase string, store map[string]Key, keyLength int) (string, error)`: Rotates the encryption key.

## License

Fcrypt is released under the BSD-3-Clause License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## Version

Current version: 0.2.0

## Authors

- Swaye Chateau (swayechateau) - Initial work

## Changelog

Detailed changes for each version are documented in the [CHANGELOG.md](CHANGELOG.md) file.