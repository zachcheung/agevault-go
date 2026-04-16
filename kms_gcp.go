package agevault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2/google"
)

// gcpKMSDecryptor implements KeyDecryptor using the GCP Cloud KMS REST API.
// Credentials are resolved via ADC: GOOGLE_APPLICATION_CREDENTIALS →
// gcloud default credentials → service account metadata server.
type gcpKMSDecryptor struct {
	// keyName is the full resource name:
	// projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	keyName string
}

func (d *gcpKMSDecryptor) token(ctx context.Context) (string, error) {
	ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloudkms")
	if err != nil {
		return "", fmt.Errorf("GCP credentials: %w", err)
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("GCP token: %w", err)
	}
	return tok.AccessToken, nil
}

func (d *gcpKMSDecryptor) doRequest(ctx context.Context, op string, body []byte) ([]byte, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://cloudkms.googleapis.com/v1/%s:%s", d.keyName, op)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GCP KMS %s: status %d: %s", op, resp.StatusCode, respBody)
	}
	return respBody, nil
}

func (d *gcpKMSDecryptor) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, err
	}
	respBody, err := d.doRequest(ctx, "decrypt", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("GCP KMS parse response: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decode plaintext: %w", err)
	}
	return plaintext, nil
}

func (d *gcpKMSDecryptor) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return nil, err
	}
	respBody, err := d.doRequest(ctx, "encrypt", body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("GCP KMS parse response: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(result.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decode ciphertext: %w", err)
	}
	return ciphertext, nil
}
