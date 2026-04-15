package agevault

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// awsKMSDecryptor implements KeyDecryptor using AWS KMS.
// Credentials are resolved via the standard AWS SDK chain:
// env vars → ~/.aws/credentials → IAM instance/task role.
type awsKMSDecryptor struct {
	// keyID is optional; AWS KMS can infer the key from the ciphertext metadata.
	keyID  string
	region string // overrides AWS_REGION / AWS_DEFAULT_REGION when non-empty
}

func (d *awsKMSDecryptor) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	var opts []func(*config.LoadOptions) error
	if d.region != "" {
		opts = append(opts, config.WithRegion(d.region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	client := kms.NewFromConfig(cfg)
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}
	if d.keyID != "" {
		input.KeyId = aws.String(d.keyID)
	}
	out, err := client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS decrypt: %w", err)
	}
	return out.Plaintext, nil
}
