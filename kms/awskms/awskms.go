// Package awskms is the AWS KMS provider for agevault. Importing it, usually
// for its side effect alone, registers the "aws" provider:
//
//	import _ "github.com/zachcheung/agevault-go/kms/awskms"
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	agevault "github.com/zachcheung/agevault-go"
)

func init() {
	agevault.RegisterKMSProvider("aws", func(cfg *agevault.Config) (agevault.KMSClient, error) {
		return &client{keyID: cfg.AWSKMSKeyID, region: cfg.AWSRegion}, nil
	})
}

// client implements agevault.KMSClient using AWS KMS.
// Credentials are resolved via the standard AWS SDK chain:
// env vars → ~/.aws/credentials → IAM instance/task role.
type client struct {
	// keyID is optional; AWS KMS can infer the key from the ciphertext metadata.
	keyID  string
	region string // overrides AWS_REGION / AWS_DEFAULT_REGION when non-empty
}

func (d *client) newClient(ctx context.Context) (*kms.Client, error) {
	var opts []func(*config.LoadOptions) error
	if d.region != "" {
		opts = append(opts, config.WithRegion(d.region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return kms.NewFromConfig(cfg), nil
}

func (d *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	c, err := d.newClient(ctx)
	if err != nil {
		return nil, err
	}
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}
	if d.keyID != "" {
		input.KeyId = aws.String(d.keyID)
	}
	out, err := c.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS decrypt: %w", err)
	}
	return out.Plaintext, nil
}

func (d *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if d.keyID == "" {
		return nil, fmt.Errorf("AWS_KMS_KEY_ID is required for --kms-out")
	}
	c, err := d.newClient(ctx)
	if err != nil {
		return nil, err
	}
	out, err := c.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(d.keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}
