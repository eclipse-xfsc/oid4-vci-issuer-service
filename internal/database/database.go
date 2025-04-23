package database

import (
	"context"
	"fmt"
	"time"
)

var ErrKeyNotFound = fmt.Errorf("key not in database")

type Database interface {
	SaveCredential(ctx context.Context, key string, credential string, ttl time.Duration) error
	GetCredential(ctx context.Context, key string) (*string, error)
	DeleteCredential(ctx context.Context, key string) (bool, error)
}
