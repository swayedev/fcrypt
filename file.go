package fcrypt

import (
	"context"
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

	return readEncryptedRecords(encryptedFile, decryptedFile, aead, chunkSize, ctx.Err)
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
		errCh <- readEncryptedRecords(encryptedFile, pw, oldAEAD, chunkSize, ctx.Err)
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
