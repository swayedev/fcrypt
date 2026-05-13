package fcrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var fileMagic = [6]byte{'F', 'C', 'R', 'Y', 'P', 'T'}

const (
	formatVersion1  byte = 1
	algorithmAESGCM byte = 1
	headerSize           = len(fileMagic) + 4
	recordLenSize        = 4
)

type formatHeader struct {
	version   byte
	algorithm byte
	nonceSize byte
	lenSize   byte
}

func writeFormatHeader(w io.Writer, aead cipher.AEAD) error {
	header := make([]byte, headerSize)
	copy(header, fileMagic[:])
	header[len(fileMagic)] = formatVersion1
	header[len(fileMagic)+1] = algorithmAESGCM
	header[len(fileMagic)+2] = byte(aead.NonceSize())
	header[len(fileMagic)+3] = recordLenSize
	_, err := w.Write(header)
	return err
}

func readFormatHeader(r io.Reader, aead cipher.AEAD) (formatHeader, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return formatHeader{}, fmt.Errorf("%w: %v", ErrInvalidFileFormat, err)
		}
		return formatHeader{}, fmt.Errorf("%w: %v", ErrFailedToReadData, err)
	}

	for i := range fileMagic {
		if header[i] != fileMagic[i] {
			return formatHeader{}, ErrInvalidFileFormat
		}
	}

	h := formatHeader{
		version:   header[len(fileMagic)],
		algorithm: header[len(fileMagic)+1],
		nonceSize: header[len(fileMagic)+2],
		lenSize:   header[len(fileMagic)+3],
	}
	if h.version != formatVersion1 {
		return formatHeader{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.version)
	}
	if h.algorithm != algorithmAESGCM {
		return formatHeader{}, fmt.Errorf("%w: %d", ErrUnsupportedAlgorithm, h.algorithm)
	}
	if int(h.nonceSize) != aead.NonceSize() || h.lenSize != recordLenSize {
		return formatHeader{}, ErrInvalidFileFormat
	}
	return h, nil
}

func maxRecordSize(chunkSize int, aead cipher.AEAD) int {
	if chunkSize > 0 {
		max := chunkSize + aead.Overhead()
		if max < MaxCiphertextRecordSize {
			return max
		}
	}
	return MaxCiphertextRecordSize
}

func writeEncryptedRecords(r io.Reader, w io.Writer, aead cipher.AEAD, chunkSize int, checkContext func() error) error {
	if chunkSize <= 0 {
		return ErrChunkSizeTooSmall
	}
	if err := writeFormatHeader(w, aead); err != nil {
		return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
	}

	chunk := make([]byte, chunkSize)
	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, recordLenSize)

	for {
		if checkContext != nil {
			if err := checkContext(); err != nil {
				return err
			}
		}

		n, readErr := r.Read(chunk)
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
		if len(ciphertext) > MaxCiphertextRecordSize {
			return fmt.Errorf("%w: %d", ErrInvalidRecordLength, len(ciphertext))
		}
		binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))

		if _, err := w.Write(nonce); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := w.Write(lenBuf); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
		if _, err := w.Write(ciphertext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
	}
	return nil
}

func readEncryptedRecords(r io.Reader, w io.Writer, aead cipher.AEAD, chunkSize int, checkContext func() error) error {
	if chunkSize <= 0 {
		return ErrChunkSizeTooSmall
	}
	if _, err := readFormatHeader(r, aead); err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	lenBuf := make([]byte, recordLenSize)
	maxLen := maxRecordSize(chunkSize, aead)

	for {
		if checkContext != nil {
			if err := checkContext(); err != nil {
				return err
			}
		}

		if _, err := io.ReadFull(r, nonce); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: nonce", ErrTruncatedRecord)
			}
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		if _, err := io.ReadFull(r, lenBuf); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: length", ErrTruncatedRecord)
			}
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		ctLen := int(binary.BigEndian.Uint32(lenBuf))
		if ctLen <= aead.Overhead() || ctLen > maxLen {
			return fmt.Errorf("%w: %d", ErrInvalidRecordLength, ctLen)
		}

		ciphertext := make([]byte, ctLen)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: ciphertext", ErrTruncatedRecord)
			}
			return fmt.Errorf("%w: %v", ErrFailedToReadData, err)
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
		}
		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("%w: %v", ErrFailedToCreateFile, err)
		}
	}
	return nil
}
