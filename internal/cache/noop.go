package cache

import (
	"context"
	"time"
)

// NoopCache is a cache that never stores anything; useful in tests.
type NoopCache struct{}

func (NoopCache) Get(_ context.Context, key string) ([]byte, error) {
	return nil, &ErrCacheMiss{Key: key}
}
func (NoopCache) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error { return nil }
func (NoopCache) Delete(_ context.Context, _ string) error                          { return nil }
