package cache

import (
	"context"
	"time"
)

// Cache is a minimal key-value cache interface.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// ErrCacheMiss is returned by Get when the key is not present.
type ErrCacheMiss struct{ Key string }

func (e *ErrCacheMiss) Error() string { return "cache miss: " + e.Key }

func IsMiss(err error) bool {
	_, ok := err.(*ErrCacheMiss)
	return ok
}
