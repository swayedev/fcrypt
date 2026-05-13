package fcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
		versioned, reader, err := hasFormatHeader(data)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if versioned {
			err = readEncryptedRecords(reader, pw, aead, DefaultChunkSize, nil)
		} else {
			err = decryptLegacyCTR(reader, pw, key)
		}
		if err != nil {
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

// LegacyStreamEncrypt encrypts a stream using the pre-0.3 AES-CTR format.
//
// This format is kept only for migration and interoperability with existing
// ciphertext. It does not provide authentication or integrity. New code should
// use StreamEncrypt.
func LegacyStreamEncrypt(data io.Reader, key []byte) (io.Reader, error) {
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
			_ = pw.CloseWithError(err)
			return
		}
		stream := cipher.NewCTR(block, nonce)
		writer := &cipher.StreamWriter{S: stream, W: pw}
		if _, err := io.Copy(writer, data); err != nil {
			_ = pw.CloseWithError(err)
		}
	}()
	return pr, nil
}

// LegacyStreamDecrypt decrypts a stream using the pre-0.3 AES-CTR format.
//
// This format does not authenticate ciphertext. It should only be used to
// migrate existing data into StreamEncrypt's authenticated format.
func LegacyStreamDecrypt(data io.Reader, key []byte) (io.Reader, error) {
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
			_ = pw.CloseWithError(err)
		}
	}()
	return pr, nil
}

func decryptLegacyCTR(data io.Reader, out io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateCipher, err)
	}

	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(data, nonce); err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}

	stream := cipher.NewCTR(block, nonce)
	reader := &cipher.StreamReader{S: stream, R: data}
	if _, err := io.Copy(out, reader); err != nil {
		return err
	}
	return nil
}
