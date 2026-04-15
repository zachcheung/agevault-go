package agevault

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// gcpKMSDecryptor implements KeyDecryptor using GCP Cloud KMS.
// Credentials are resolved via the standard GCP SDK chain:
// GOOGLE_APPLICATION_CREDENTIALS env var → gcloud default credentials → service account.
type gcpKMSDecryptor struct {
	// keyName is the full resource name of the KMS key version:
	// projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}
	keyName string
}

func (d *gcpKMSDecryptor) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create GCP KMS client: %w", err)
	}
	defer client.Close()

	out, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       d.keyName,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decrypt: %w", err)
	}
	return out.Plaintext, nil
}
