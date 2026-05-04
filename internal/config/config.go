package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	DB       DBConfig
	Redis    RedisConfig
	Upstream UpstreamConfig
	Proxy    ProxyConfig
}

type ServerConfig struct {
	Port         int
	AdminPort    int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DBConfig holds SQLite connection settings.
// DSN is empty by default (log-only mode — no DB recording).
// Use "file:./downloads.db" for a persistent local file, or ":memory:" for tests.
type DBConfig struct {
	DSN string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type UpstreamConfig struct {
	NPM        string
	PyPI       string
	Gems       string
	Composer   string
	Brew       string
	Docker     string
	Maven      string
	NuGet      string
	CargoIndex string
	CargoAPI   string
	GoMod      string
}

type ProxyConfig struct {
	// Public base URL used to rewrite package archive URLs in metadata responses.
	// e.g. "https://npm.registry-gate.example.com"
	NPMBaseURL string
	BaseURL    string
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         envInt("PORT", 8080),
			AdminPort:    envInt("ADMIN_PORT", 8081),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		DB: DBConfig{
			DSN: envStr("DATABASE_URL", ""),
		},
		Redis: RedisConfig{
			Addr:     envStr("REDIS_ADDR", ""),
			Password: envStr("REDIS_PASSWORD", ""),
			DB:       envInt("REDIS_DB", 0),
		},
		Upstream: UpstreamConfig{
			NPM:        envStr("UPSTREAM_NPM", "https://registry.npmjs.org"),
			PyPI:       envStr("UPSTREAM_PYPI", "https://pypi.org"),
			Gems:       envStr("UPSTREAM_GEMS", "https://rubygems.org"),
			Composer:   envStr("UPSTREAM_COMPOSER", "https://repo.packagist.org"),
			Brew:       envStr("UPSTREAM_BREW", "https://ghcr.io"),
			Docker:     envStr("UPSTREAM_DOCKER", "https://registry-1.docker.io"),
			Maven:      envStr("UPSTREAM_MAVEN", "https://repo1.maven.org/maven2"),
			NuGet:      envStr("UPSTREAM_NUGET", "https://api.nuget.org/v3/index.json"),
			CargoIndex: envStr("UPSTREAM_CARGO_INDEX", "https://index.crates.io"),
			CargoAPI:   envStr("UPSTREAM_CARGO_API", "https://crates.io"),
			GoMod:      envStr("UPSTREAM_GOMOD", "https://proxy.golang.org"),
		},
		Proxy: ProxyConfig{
			BaseURL:    envStr("PROXY_BASE_URL", envStr("PROXY_NPM_BASE_URL", "http://localhost:8080")),
			NPMBaseURL: envStr("PROXY_BASE_URL", envStr("PROXY_NPM_BASE_URL", "http://localhost:8080")),
		},
	}

	return cfg, nil
}

func envStr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
