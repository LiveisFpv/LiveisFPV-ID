package storage

import (
	"authorization_service/internal/config"
	"context"
	"fmt"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func MinioConnect(ctx context.Context, cfg config.MinioConfig) (*minio.Client, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Minio: %v", err)
	}

	// Check if the bucket exists
	exists, errBucket := client.BucketExists(ctx, cfg.BucketName)
	if errBucket != nil {
		return nil, fmt.Errorf("failed to check bucket existence: %v", errBucket)
	}

	if !exists {
		return nil, fmt.Errorf("bucket %s does not exist", cfg.BucketName)
	}

	return client, nil
}
