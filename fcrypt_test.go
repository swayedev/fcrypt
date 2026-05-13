package fcrypt_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/swayedev/fcrypt"
	"golang.org/x/crypto/sha3"
)

func TestGenerateSalt(t *testing.T) {
	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("Expected salt length of 16, got %d", len(salt))
	}
}

func TestGenerateKey(t *testing.T) {
	passphrase := "test-passphrase"
	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	if len(key) != fcrypt.DefaultKeyLength {
		t.Errorf("Expected key length of %d, got %d", fcrypt.DefaultKeyLength, len(key))
	}
}

// TestGenerateSaltAndKey tests the GenerateSaltAndKey function.
func TestGenerateSaltAndKey(t *testing.T) {
	passphrase := "your-passphrase"
	saltLength := 16
	keyLength := 32

	salt1, key1, err1 := fcrypt.GenerateSaltAndKey(passphrase, saltLength, keyLength)
	if err1 != nil {
		t.Fatalf("expected no error, got %v", err1)
	}

	salt2, key2, err2 := fcrypt.GenerateSaltAndKey(passphrase, saltLength, keyLength)
	if err2 != nil {
		t.Fatalf("expected no error, got %v", err2)
	}

	// Check that the salt and key are of the correct length
	if len(salt1) != saltLength {
		t.Fatalf("expected salt length %d, got %d", saltLength, len(salt1))
	}

	if len(key1) != keyLength {
		t.Fatalf("expected key length %d, got %d", keyLength, len(key1))
	}

	// Check that two different salt and key pairs are generated
	if bytes.Equal(salt1, salt2) && bytes.Equal(key1, key2) {
		t.Fatalf("expected different salt and key pairs, got the same")
	}

	t.Logf("Salt1: %x", salt1)
	t.Logf("Key1: %x", key1)
	t.Logf("Salt2: %x", salt2)
	t.Logf("Key2: %x", key2)
}

func TestEncryptDecrypt(t *testing.T) {
	passphrase := "test-passphrase"
	data := []byte("Sensitive data here")

	// Generate salt and key
	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encrypt data
	encryptedData, err := fcrypt.Encrypt(data, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt data
	decryptedData, err := fcrypt.Decrypt(encryptedData, key)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify decrypted data
	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted data does not match original data. Expected %s, got %s", data, decryptedData)
	}
}

func TestHashing(t *testing.T) {
	data := "Sensitive data here"
	expectedSHA3Hash := fcrypt.HashStringToString(data, sha3.New256())
	actualSHA3Hash := fcrypt.HashStringToString(data, sha3.New256())
	if expectedSHA3Hash != actualSHA3Hash {
		t.Errorf("SHA3-256 hash mismatch. Expected %s, got %s", expectedSHA3Hash, actualSHA3Hash)
	}

	file, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	_, err = file.WriteString(data)
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	file.Seek(0, 0)

	hashedFileSHA3, err := fcrypt.HashFileSHA3(file)
	if err != nil {
		t.Fatalf("Failed to hash file: %v", err)
	}

	expectedHashedFileSHA3 := fcrypt.HashBytesSHA3([]byte(data))
	if !bytes.Equal(hashedFileSHA3, expectedHashedFileSHA3) {
		t.Errorf("SHA3-256 file hash mismatch. Expected %x, got %x", expectedHashedFileSHA3, hashedFileSHA3)
	}
}

func TestEncryptFileToFile(t *testing.T) {
	passphrase := "test-passphrase"
	data := []byte("Sensitive data here")

	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	inputFile, err := os.CreateTemp("", "inputfile")
	if err != nil {
		t.Fatalf("Failed to create temp input file: %v", err)
	}
	defer os.Remove(inputFile.Name())

	_, err = inputFile.Write(data)
	if err != nil {
		t.Fatalf("Failed to write to input file: %v", err)
	}
	inputFile.Seek(0, 0)

	outputFile := inputFile.Name() + ".encrypted"
	defer os.Remove(outputFile)

	if err := fcrypt.EncryptFileToFile(inputFile, key, 4096, outputFile); err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	decryptedOutputFile := inputFile.Name() + ".decrypted"
	defer os.Remove(decryptedOutputFile)

	if err := fcrypt.DecryptFileToFile(outputFile, decryptedOutputFile, key, 4096); err != nil {
		t.Fatalf("Failed to decrypt file: %v", err)
	}

	decryptedData, err := os.ReadFile(decryptedOutputFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted file data does not match original data. Expected %s, got %s", data, decryptedData)
	}
}

func TestStreamEncryptDecrypt(t *testing.T) {
	passphrase := "test-passphrase"
	data := []byte("Sensitive data here")

	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}
	key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	dataReader := bytes.NewReader(data)
	encryptedStream, err := fcrypt.StreamEncrypt(dataReader, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data stream: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedStream)
	if err != nil {
		t.Fatalf("Failed to read encrypted stream: %v", err)
	}

	decryptedStream, err := fcrypt.StreamDecrypt(bytes.NewReader(encryptedData), key)
	if err != nil {
		t.Fatalf("Failed to decrypt data stream: %v", err)
	}

	decryptedData, err := io.ReadAll(decryptedStream)
	if err != nil {
		t.Fatalf("Failed to read decrypted stream: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted stream data does not match original data. Expected %s, got %s", data, decryptedData)
	}
}

func TestEncryptedFileHasVersionedHeader(t *testing.T) {
	key := bytes.Repeat([]byte{1}, fcrypt.DefaultKeyLength)
	input := bytes.NewReader([]byte("hello header"))
	outputFile := t.TempDir() + "/header.fcrypt"

	if err := fcrypt.EncryptFileToFile(input, key, 4096, outputFile); err != nil {
		t.Fatalf("EncryptFileToFile() error = %v", err)
	}

	encrypted, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(encrypted[:6], []byte("FCRYPT")) {
		t.Fatalf("missing fcrypt magic header: %q", encrypted[:6])
	}
	if encrypted[6] != 1 {
		t.Fatalf("unexpected format version: %d", encrypted[6])
	}
}

func TestDecryptFileRejectsOversizedRecord(t *testing.T) {
	key := bytes.Repeat([]byte{2}, fcrypt.DefaultKeyLength)
	dir := t.TempDir()
	encryptedFile := dir + "/oversized.fcrypt"
	decryptedFile := dir + "/oversized.txt"

	if err := fcrypt.EncryptFileToFile(bytes.NewReader([]byte("hello oversized")), key, 4096, encryptedFile); err != nil {
		t.Fatalf("EncryptFileToFile() error = %v", err)
	}

	encrypted, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lengthOffset := 10 + 12
	binary.BigEndian.PutUint32(encrypted[lengthOffset:lengthOffset+4], uint32(fcrypt.MaxCiphertextRecordSize+1))
	if err := os.WriteFile(encryptedFile, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err = fcrypt.DecryptFileToFile(encryptedFile, decryptedFile, key, 4096)
	if !errors.Is(err, fcrypt.ErrInvalidRecordLength) {
		t.Fatalf("DecryptFileToFile() error = %v, want ErrInvalidRecordLength", err)
	}
}

func TestStreamDecryptRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{3}, fcrypt.DefaultKeyLength)
	encryptedStream, err := fcrypt.StreamEncrypt(bytes.NewReader([]byte("hello tamper")), key)
	if err != nil {
		t.Fatalf("StreamEncrypt() error = %v", err)
	}
	encrypted, err := io.ReadAll(encryptedStream)
	if err != nil {
		t.Fatalf("ReadAll(encryptedStream) error = %v", err)
	}
	encrypted[len(encrypted)-1] ^= 0x01

	decryptedStream, err := fcrypt.StreamDecrypt(bytes.NewReader(encrypted), key)
	if err != nil {
		t.Fatalf("StreamDecrypt() error = %v", err)
	}
	_, err = io.ReadAll(decryptedStream)
	if !errors.Is(err, fcrypt.ErrAuthenticationFailed) {
		t.Fatalf("ReadAll(decryptedStream) error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestNewHasher(t *testing.T) {
	hasher, err := fcrypt.NewHasher(fcrypt.HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("NewHasher() error = %v", err)
	}
	got := fcrypt.HashBytesToString([]byte("hello"), hasher)
	want := fcrypt.HashBytesToStringSHA256([]byte("hello"))
	if got != want {
		t.Fatalf("hash mismatch: got %s want %s", got, want)
	}

	if _, err := fcrypt.NewHasher(fcrypt.HashAlgorithm("unknown")); !errors.Is(err, fcrypt.ErrUnsupportedHash) {
		t.Fatalf("NewHasher(unknown) error = %v, want ErrUnsupportedHash", err)
	}
}

func TestReEncrypt(t *testing.T) {
	passphrase := "test-passphrase"
	data := []byte("Sensitive data here")

	salt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := fcrypt.GenerateKey(passphrase, salt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptedData, err := fcrypt.Encrypt(data, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	newSalt, err := fcrypt.GenerateSalt(16)
	if err != nil {
		t.Fatalf("Failed to generate new salt: %v", err)
	}

	newKey, err := fcrypt.GenerateKey(passphrase, newSalt, fcrypt.DefaultKeyLength)
	if err != nil {
		t.Fatalf("Failed to generate new key: %v", err)
	}

	reEncryptedData, err := fcrypt.ReEncrypt(encryptedData, key, newKey)
	if err != nil {
		t.Fatalf("Failed to re-encrypt data: %v", err)
	}

	decryptedData, err := fcrypt.Decrypt(reEncryptedData, newKey)
	if err != nil {
		t.Fatalf("Failed to decrypt re-encrypted data: %v", err)
	}

	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted re-encrypted data does not match original data. Expected %s, got %s", data, decryptedData)
	}
}
