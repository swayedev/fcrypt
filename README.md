# Fcrypt

Fcrypt is a flexible and secure encryption package for Go, providing easy-to-use functions for encrypting and decrypting data using AES-GCM (Galois/Counter Mode). This package is designed for simplicity and security, making it suitable for various applications requiring data protection.

## Features

- Encrypt and decrypt data with AES-GCM.
- Stream encryption and decryption.
- Key rotation and re-encryption support.
- Extensible key management with an interface for different key types.
- Hashing functions using SHA3-256.

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

Fcrypt includes hashing functions using SHA3-256:

```go
package main

import (
    "fmt"

    "github.com/swayedev/fcrypt"
)

func main() {
    data := "Sensitive data here"

    // Hash string to string
    hashedString := fcrypt.HashStringToString(data)
    fmt.Printf("Hashed string: %s\n", hashedString)

    // Hash string to byte array
    hashedArray := fcrypt.HashString(data)
    fmt.Printf("Hashed array: %x\n", hashedArray)

    // Hash byte slice
    hashedBytes := fcrypt.HashByte([]byte(data))
    fmt.Printf("Hashed bytes: %x\n", hashedBytes)
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
- `ErrCiphertextTooShort`: Error message for short ciphertext.
- `ErrKeyLengthTooShort`: Error message for short key length.

### Functions

- `GenerateSalt(length int) ([]byte, error)`: Generates a random salt.
- `GenerateKey(passphrase string, salt []byte, keyLength int) ([]byte, error)`: Generates a key using scrypt.
- `GenerateGCM(key []byte) (cipher.AEAD, cipher.Block, error)`: Generates a GCM cipher.
- `Encrypt(data []byte, key []byte) ([]byte, error)`: Encrypts data.
- `Decrypt(data []byte, key []byte) ([]byte, error)`: Decrypts data.
- `ReEncrypt(data []byte, oldKey []byte, newKey []byte) ([]byte, error)`: Re-encrypts data with a new key.
- `StreamEncrypt(data io.Reader, key []byte) (io.Reader, error)`: Encrypts data stream.
- `StreamDecrypt(data io.Reader, key []byte) (io.Reader, error)`: Decrypts data stream.
- `StreamReEncrypt(data io.Reader, oldKey []byte, newKey []byte) (io.Reader, error)`: Re-encrypts data stream with a new key.
- `HashStringToString(data string) string`: Hashes a string and returns a hexadecimal string.
- `HashString(data string) [32]byte`: Hashes a string and returns a 32-byte array.
- `HashByte(data []byte) [32]byte`: Hashes a byte slice and returns a 32-byte array.
- `RotateKey(passphrase string, store map[string]Key, keyLength int) (string, error)`: Rotates the encryption key.

## License

Fcrypt is released under the BSD-3-Clause License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## Version

Current version: 0.1.0

## Authors

- Swaye Chateau (swayechateau) - Initial work

