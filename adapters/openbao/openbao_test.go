package openbao_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/swayedev/fcrypt"
	"github.com/swayedev/fcrypt/adapters/openbao"
)

func TestOpenBaoTransitWrapper(t *testing.T) {
	client, err := openbao.New(openbao.Config{
		Address: "https://openbao.test",
		Token:   "token",
		KeyName: "fcrypt",
		HTTPClient: &http.Client{
			Transport: transitTransport{prefix: "bao:"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	key := []byte("data-key")
	wrapped, err := client.WrapKey(t.Context(), key, fcrypt.WrapOptions{AAD: []byte("ctx")})
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	unwrapped, err := client.UnwrapKey(t.Context(), wrapped)
	if err != nil {
		t.Fatalf("UnwrapKey() error = %v", err)
	}
	if string(unwrapped) != string(key) {
		t.Fatalf("UnwrapKey() = %q, want %q", unwrapped, key)
	}
}

type transitTransport struct {
	prefix string
}

func (t transitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	data := map[string]string{}
	switch {
	case strings.Contains(r.URL.Path, "/encrypt/"):
		plain, _ := base64.StdEncoding.DecodeString(req["plaintext"])
		data["ciphertext"] = t.prefix + base64.StdEncoding.EncodeToString(plain)
	case strings.Contains(r.URL.Path, "/decrypt/"):
		ciphertext := req["ciphertext"]
		plain, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, t.prefix))
		data["plaintext"] = base64.StdEncoding.EncodeToString(plain)
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}

	body, err := json.Marshal(map[string]map[string]string{"data": data})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}, nil
}
