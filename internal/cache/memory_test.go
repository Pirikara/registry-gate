package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/pirikara/registory-gate/internal/cache"
)

func TestMemoryCache_GetMiss(t *testing.T) {
	c := cache.NewMemoryCache()
	_, err := c.Get(context.Background(), "missing")
	if !cache.IsMiss(err) {
		t.Fatalf("expected cache miss, got %v", err)
	}
}

func TestMemoryCache_SetGet(t *testing.T) {
	c := cache.NewMemoryCache()
	ctx := context.Background()
	want := []byte("hello")
	if err := c.Set(ctx, "k", want, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMemoryCache_TTLExpiry(t *testing.T) {
	c := cache.NewMemoryCache()
	ctx := context.Background()
	if err := c.Set(ctx, "k", []byte("v"), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	_, err := c.Get(ctx, "k")
	if !cache.IsMiss(err) {
		t.Fatalf("expected cache miss after TTL expiry, got %v", err)
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	c := cache.NewMemoryCache()
	ctx := context.Background()
	_ = c.Set(ctx, "k", []byte("v"), time.Minute)
	_ = c.Delete(ctx, "k")
	_, err := c.Get(ctx, "k")
	if !cache.IsMiss(err) {
		t.Fatalf("expected cache miss after delete, got %v", err)
	}
}

func TestMemoryCache_Overwrite(t *testing.T) {
	c := cache.NewMemoryCache()
	ctx := context.Background()
	_ = c.Set(ctx, "k", []byte("first"), time.Minute)
	_ = c.Set(ctx, "k", []byte("second"), time.Minute)
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("got %q, want 'second'", got)
	}
}

func TestNoopCache_AlwaysMisses(t *testing.T) {
	var c cache.NoopCache
	ctx := context.Background()
	_ = c.Set(ctx, "k", []byte("v"), time.Minute)
	_, err := c.Get(ctx, "k")
	if !cache.IsMiss(err) {
		t.Fatalf("NoopCache.Get should always return a miss, got %v", err)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("NoopCache.Delete: %v", err)
	}
}

func TestIsMiss(t *testing.T) {
	if cache.IsMiss(nil) {
		t.Error("IsMiss(nil) should be false")
	}
	if !cache.IsMiss(&cache.ErrCacheMiss{Key: "x"}) {
		t.Error("IsMiss(*ErrCacheMiss) should be true")
	}
}
