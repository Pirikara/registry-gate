package cache

import (
	"context"
	"sync"
	"time"
)

type memEntry struct {
	data      []byte
	expiresAt time.Time
}

// MemoryCache is an in-process cache backed by sync.Map with TTL expiry.
// Expired entries are evicted lazily on Get.
type MemoryCache struct {
	m sync.Map
}

func NewMemoryCache() *MemoryCache { return &MemoryCache{} }

func (c *MemoryCache) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := c.m.Load(key)
	if !ok {
		return nil, &ErrCacheMiss{Key: key}
	}
	e := v.(memEntry)
	if time.Now().After(e.expiresAt) {
		c.m.Delete(key)
		return nil, &ErrCacheMiss{Key: key}
	}
	return e.data, nil
}

func (c *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.m.Store(key, memEntry{data: value, expiresAt: time.Now().Add(ttl)})
	return nil
}

func (c *MemoryCache) Delete(_ context.Context, key string) error {
	c.m.Delete(key)
	return nil
}
