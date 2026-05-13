package fcrypt

import (
	"fmt"
	"io"
)

// StreamEncrypt takes an input stream and returns an authenticated AES-GCM record stream.
func StreamEncrypt(data io.Reader, key []byte) (io.Reader, error) {
	aead, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := writeEncryptedRecords(data, pw, aead, DefaultChunkSize, nil); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, nil
}

// StreamDecrypt decrypts an authenticated AES-GCM record stream.
func StreamDecrypt(data io.Reader, key []byte) (io.Reader, error) {
	aead, _, err := GenerateGCM(key)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		if err := readEncryptedRecords(data, pw, aead, DefaultChunkSize, nil); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, nil
}

// StreamReEncrypt re-encrypts the data from the given reader using oldKey and newKey.
func StreamReEncrypt(data io.Reader, oldKey []byte, newKey []byte) (io.Reader, error) {
	decryptedStream, err := StreamDecrypt(data, oldKey)
	if err != nil {
		return nil, err
	}
	encryptedStream, err := StreamEncrypt(decryptedStream, newKey)
	if err != nil {
		return nil, fmt.Errorf("stream re-encrypt: %w", err)
	}
	return encryptedStream, nil
}
