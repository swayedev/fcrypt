package fcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// StreamEncrypt takes an input data stream and a key, and returns an encrypted data stream along with any error encountered.
//
// NOTE: This uses AES-CTR and does not provide authentication/integrity.
func StreamEncrypt(data io.Reader, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}

	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if _, err := pw.Write(nonce); err != nil {
			pw.CloseWithError(err)
			return
		}
		stream := cipher.NewCTR(block, nonce)
		writer := &cipher.StreamWriter{S: stream, W: pw}
		if _, err := io.Copy(writer, data); err != nil {
			pw.CloseWithError(err)
		}
	}()
	return pr, nil
}

// StreamDecrypt decrypts the data from the given io.Reader using the provided key.
//
// NOTE: This uses AES-CTR and does not provide authentication/integrity.
func StreamDecrypt(data io.Reader, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}

	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(data, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		stream := cipher.NewCTR(block, nonce)
		reader := &cipher.StreamReader{S: stream, R: data}
		if _, err := io.Copy(pw, reader); err != nil {
			pw.CloseWithError(err)
		}
	}()
	return pr, nil
}

// StreamReEncrypt re-encrypts the data from the given reader using the oldKey and then encrypts it again using the newKey.
func StreamReEncrypt(data io.Reader, oldKey []byte, newKey []byte) (io.Reader, error) {
	decryptedStream, err := StreamDecrypt(data, oldKey)
	if err != nil {
		return nil, err
	}
	return StreamEncrypt(decryptedStream, newKey)
}
