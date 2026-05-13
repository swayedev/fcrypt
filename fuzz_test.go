package fcrypt

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func FuzzDecrypt(f *testing.F) {
	key := bytes.Repeat([]byte{1}, DefaultKeyLength)
	ciphertext, err := Encrypt([]byte("seed"), key)
	if err != nil {
		f.Fatalf("Encrypt() seed error = %v", err)
	}
	f.Add(ciphertext)
	f.Add([]byte{})
	f.Add([]byte("short"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decrypt(data, key)
	})
}

func FuzzReadEncryptedRecords(f *testing.F) {
	key := bytes.Repeat([]byte{2}, DefaultKeyLength)
	var buf bytes.Buffer
	aead, _, err := GenerateGCM(key)
	if err != nil {
		f.Fatalf("GenerateGCM() seed error = %v", err)
	}
	if err := writeEncryptedRecords(bytes.NewReader([]byte("seed")), &buf, aead, 32, context.Background().Err); err != nil {
		f.Fatalf("writeEncryptedRecords() seed error = %v", err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte("FCRYPT\x01\x01\x0c\x04"))
	f.Add([]byte("not-fcrypt"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = readAnyEncryptedRecords(bytes.NewReader(data), io.Discard, aead, 32, context.Background().Err)
	})
}
