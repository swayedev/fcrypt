package fcrypt

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// EncryptFileToFile encrypts data from the reader into a versioned AES-GCM record file.
func EncryptFileToFile(data io.Reader, key []byte, chunkSize int, filePath string) error {
	return EncryptFileToFileWithContext(context.Background(), data, key, chunkSize, filePath)
}

func EncryptFileToFileWithContext(ctx context.Context, data io.Reader, key []byte, chunkSize int, filePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	aead, _, err := GenerateGCM(key)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer file.Close()

	return writeEncryptedRecords(data, file, aead, chunkSize, ctx.Err)
}

// DecryptFileToFile decrypts a versioned AES-GCM record file and writes plaintext to a new file.
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

	aead, _, err := GenerateGCM(key)
	if err != nil {
		return err
	}

	return readAnyEncryptedRecords(encryptedFile, decryptedFile, aead, chunkSize, ctx.Err)
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

	oldAEAD, _, err := GenerateGCM(oldKey)
	if err != nil {
		return err
	}
	newAEAD, _, err := GenerateGCM(newKey)
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		defer pw.Close()
		errCh <- readAnyEncryptedRecords(encryptedFile, pw, oldAEAD, chunkSize, ctx.Err)
	}()

	if err := writeEncryptedRecords(pr, outFile, newAEAD, chunkSize, ctx.Err); err != nil {
		_ = pr.Close()
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}
	return nil
}

// LegacyEncryptFileToFile writes the pre-0.3 AES-GCM record format without a file header.
//
// This is kept only for compatibility tests and controlled migration workflows.
// New code should use EncryptFileToFile.
func LegacyEncryptFileToFile(data io.Reader, key []byte, chunkSize int, filePath string) error {
	if chunkSize <= 0 {
		return ErrChunkSizeTooSmall
	}

	aead, _, err := GenerateGCM(key)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}
	defer file.Close()

	chunk := make([]byte, chunkSize)
	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, recordLenSize)

	for {
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
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
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
