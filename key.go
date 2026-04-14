package agevault

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// KeyGet fetches the public key for a username from AGE_KEY_SERVER.
// Supports http(s):// and file:// URLs.
func (v *Vault) KeyGet(username string) (string, error) {
	if v.Config.KeyServer == "" {
		return "", fmt.Errorf("AGE_KEY_SERVER is not set")
	}
	url := fmt.Sprintf("%s/%s.%s", v.Config.KeyServer, username, v.Config.PubkeyExt)

	var data []byte
	var err error
	if strings.HasPrefix(url, "file://") {
		path := strings.TrimPrefix(url, "file://")
		data, err = os.ReadFile(path)
	} else {
		data, err = httpGet(url)
	}
	if err != nil {
		return "", fmt.Errorf("fetch key for %s: %w", username, err)
	}
	return string(data), nil
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// KeyAdd fetches public keys for the given usernames from AGE_KEY_SERVER
// and appends them to AGE_RECIPIENTS_FILE.
func (v *Vault) KeyAdd(users ...string) error {
	if len(users) == 0 {
		return fmt.Errorf("missing users")
	}
	for _, u := range users {
		key, err := v.KeyGet(u)
		if err != nil {
			return err
		}
		rf := v.Config.RecipientsFile
		f, err := os.OpenFile(rf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open recipients file %s: %w", rf, err)
		}
		_, writeErr := fmt.Fprint(f, key)
		f.Close()
		if writeErr != nil {
			return writeErr
		}
		fmt.Printf("added '%s' to '%s'.\n", u, rf)
	}
	return nil
}

// KeyReadd truncates AGE_RECIPIENTS_FILE and re-adds public keys for the
// given usernames from AGE_KEY_SERVER.
func (v *Vault) KeyReadd(users ...string) error {
	if len(users) == 0 {
		return fmt.Errorf("missing users")
	}
	if err := os.WriteFile(v.Config.RecipientsFile, nil, 0644); err != nil {
		return fmt.Errorf("truncate recipients file %s: %w", v.Config.RecipientsFile, err)
	}
	return v.KeyAdd(users...)
}
