package fcrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// EncryptFileToFile encrypts the data from the given reader using the provided key and writes it to the specified file.
func EncryptFileToFile(data io.Reader, key []byte, chunkSize int, filePath string) error {
	return EncryptFileToFileWithContext(context.Background(), data, key, chunkSize, filePath)
}

func EncryptFileToFileWithContext(ctx context.Context, data io.Reader, key []byte, chunkSize int, filePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if chunkSize <= 0 {
		return ErrChunkSizeTooSmall
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateGCM, err)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer file.Close()

	chunk := make([]byte, chunkSize)
	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, 4)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := data.Read(chunk)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, readErr)
		}

		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		ciphertext := aead.Seal(nil, nonce, chunk[:n], nil)
		if len(ciphertext) > int(^uint32(0)) {
			return fmt.Errorf("ciphertext chunk too large: %d", len(ciphertext))
		}

		binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))

		// Record format: nonce || uint32(ciphertextLen) || ciphertext
		if _, err := file.Write(nonce); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := file.Write(lenBuf); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := file.Write(ciphertext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
	}

	return nil
}

// DecryptFileToFile decrypts the contents of an encrypted file and writes the decrypted data to a new file.
func DecryptFileToFile(encryptedFilePath, decryptedFilePath string, key []byte, chunkSize int) error {
	return DecryptFileToFileWithContext(context.Background(), encryptedFilePath, decryptedFilePath, key, chunkSize)
}

func DecryptFileToFileWithContext(ctx context.Context, encryptedFilePath, decryptedFilePath string, key []byte, chunkSize int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer encryptedFile.Close()

	decryptedFile, err := os.OpenFile(decryptedFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer decryptedFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateGCM, err)
	}

	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, 4)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if _, err := io.ReadFull(encryptedFile, nonce); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		if _, err := io.ReadFull(encryptedFile, lenBuf); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		ctLen := binary.BigEndian.Uint32(lenBuf)
		if ctLen == 0 {
			return fmt.Errorf("invalid ciphertext length: 0")
		}

		ciphertext := make([]byte, int(ctLen))
		if _, err := io.ReadFull(encryptedFile, ciphertext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
		}

		if _, err := decryptedFile.Write(plaintext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
	}

	_ = chunkSize
	return nil
}

// ReEncryptFileToFile re-encrypts an encrypted file from oldKey to newKey.
func ReEncryptFileToFile(encryptedFilePath, decryptedFilePath string, oldKey []byte, newKey []byte, chunkSize int) error {
	return ReEncryptFileToFileWithContext(context.Background(), encryptedFilePath, decryptedFilePath, oldKey, newKey, chunkSize)
}

func ReEncryptFileToFileWithContext(ctx context.Context, encryptedFilePath, decryptedFilePath string, oldKey []byte, newKey []byte, chunkSize int) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer encryptedFile.Close()

	outFile, err := os.OpenFile(decryptedFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer outFile.Close()

	oldBlock, err := aes.NewCipher(oldKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}
	oldAEAD, err := cipher.NewGCM(oldBlock)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateGCM, err)
	}

	newBlock, err := aes.NewCipher(newKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}
	newAEAD, err := cipher.NewGCM(newBlock)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateGCM, err)
	}

	nonce := make([]byte, oldAEAD.NonceSize())
	lenBuf := make([]byte, 4)
	newNonce := make([]byte, newAEAD.NonceSize())
	outLenBuf := make([]byte, 4)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if _, err := io.ReadFull(encryptedFile, nonce); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}
		if _, err := io.ReadFull(encryptedFile, lenBuf); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		ctLen := binary.BigEndian.Uint32(lenBuf)
		if ctLen == 0 {
			return fmt.Errorf("invalid ciphertext length: 0")
		}

		ciphertext := make([]byte, int(ctLen))
		if _, err := io.ReadFull(encryptedFile, ciphertext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		plaintext, err := oldAEAD.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
		}

		if _, err := io.ReadFull(rand.Reader, newNonce); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}
		newCiphertext := newAEAD.Seal(nil, newNonce, plaintext, nil)
		binary.BigEndian.PutUint32(outLenBuf, uint32(len(newCiphertext)))

		if _, err := outFile.Write(newNonce); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := outFile.Write(outLenBuf); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := outFile.Write(newCiphertext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
	}

	_ = chunkSize
	return nil
}
