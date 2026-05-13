// Package vault provides a HashiCorp Vault transit adapter for fcrypt key wrapping.
package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/swayedev/fcrypt"
)

// Config configures a Vault transit client.
type Config struct {
	Address    string
	Token      string
	Mount      string
	KeyName    string
	HTTPClient *http.Client
}

// Client wraps and unwraps data keys using Vault transit.
type Client struct {
	address string
	token   string
	mount   string
	keyName string
	http    *http.Client
}

// New creates a Vault transit adapter.
func New(config Config) (*Client, error) {
	if config.Address == "" || config.Token == "" || config.KeyName == "" {
		return nil, fcrypt.ErrInvalidKey
	}
	mount := config.Mount
	if mount == "" {
		mount = "transit"
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		address: strings.TrimRight(config.Address, "/"),
		token:   config.Token,
		mount:   strings.Trim(mount, "/"),
		keyName: strings.Trim(config.KeyName, "/"),
		http:    httpClient,
	}, nil
}

// WrapKey wraps plaintextKey with Vault transit.
func (c *Client) WrapKey(ctx context.Context, plaintextKey []byte, opts fcrypt.WrapOptions) (fcrypt.WrappedKey, error) {
	if err := ctx.Err(); err != nil {
		return fcrypt.WrappedKey{}, err
	}
	if len(plaintextKey) == 0 {
		return fcrypt.WrappedKey{}, fcrypt.ErrInvalidKey
	}
	keyName := c.keyName
	if opts.KeyID != "" {
		keyName = opts.KeyID
	}
	resp, err := c.call(ctx, "encrypt", keyName, map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintextKey),
		"context":   base64.StdEncoding.EncodeToString(opts.AAD),
	})
	if err != nil {
		return fcrypt.WrappedKey{}, err
	}
	ciphertext := resp["ciphertext"]
	if ciphertext == "" {
		return fcrypt.WrappedKey{}, fcrypt.ErrInvalidWrappedKey
	}
	return fcrypt.WrappedKey{
		KeyID:      keyName,
		Algorithm:  "vault-transit",
		Ciphertext: []byte(ciphertext),
		AAD:        cloneBytes(opts.AAD),
	}, nil
}

// UnwrapKey unwraps a key with Vault transit.
func (c *Client) UnwrapKey(ctx context.Context, wrapped fcrypt.WrappedKey) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keyName := c.keyName
	if wrapped.KeyID != "" {
		keyName = wrapped.KeyID
	}
	resp, err := c.call(ctx, "decrypt", keyName, map[string]string{
		"ciphertext": string(wrapped.Ciphertext),
		"context":    base64.StdEncoding.EncodeToString(wrapped.AAD),
	})
	if err != nil {
		return nil, err
	}
	plaintext := resp["plaintext"]
	if plaintext == "" {
		return nil, fcrypt.ErrInvalidWrappedKey
	}
	return base64.StdEncoding.DecodeString(plaintext)
}

func (c *Client) call(ctx context.Context, action string, keyName string, payload map[string]string) (map[string]string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/v1/%s/%s/%s", c.address, c.mount, action, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", c.token)

	httpResp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: vault transit status %d", fcrypt.ErrInvalidWrappedKey, httpResp.StatusCode)
	}

	var decoded struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, err
	}
	return decoded.Data, nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
