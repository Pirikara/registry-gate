package config_test

import (
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/config"
)

func TestLoad_Defaults(t *testing.T) {
	for _, k := range []string{
		"PORT", "ADMIN_PORT", "DATABASE_URL",
		"REDIS_ADDR", "REDIS_PASSWORD", "REDIS_DB",
		"UPSTREAM_NPM", "UPSTREAM_PYPI", "UPSTREAM_GEMS", "UPSTREAM_COMPOSER", "UPSTREAM_BREW", "UPSTREAM_DOCKER",
		"UPSTREAM_MAVEN", "UPSTREAM_NUGET", "UPSTREAM_CARGO_INDEX", "UPSTREAM_CARGO_API", "UPSTREAM_GOMOD",
		"PROXY_BASE_URL", "PROXY_NPM_BASE_URL",
	} {
		t.Setenv(k, "")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Server.Port", cfg.Server.Port, 8080},
		{"Server.AdminPort", cfg.Server.AdminPort, 8081},
		{"Server.ReadTimeout", cfg.Server.ReadTimeout, 30 * time.Second},
		{"Server.WriteTimeout", cfg.Server.WriteTimeout, 30 * time.Second},
		{"DB.DSN", cfg.DB.DSN, ""},
		{"Redis.Addr", cfg.Redis.Addr, ""},
		{"Upstream.NPM", cfg.Upstream.NPM, "https://registry.npmjs.org"},
		{"Upstream.PyPI", cfg.Upstream.PyPI, "https://pypi.org"},
		{"Upstream.Gems", cfg.Upstream.Gems, "https://rubygems.org"},
		{"Upstream.Composer", cfg.Upstream.Composer, "https://repo.packagist.org"},
		{"Upstream.Brew", cfg.Upstream.Brew, "https://ghcr.io"},
		{"Upstream.Docker", cfg.Upstream.Docker, "https://registry-1.docker.io"},
		{"Upstream.Maven", cfg.Upstream.Maven, "https://repo1.maven.org/maven2"},
		{"Upstream.NuGet", cfg.Upstream.NuGet, "https://api.nuget.org/v3/index.json"},
		{"Upstream.CargoIndex", cfg.Upstream.CargoIndex, "https://index.crates.io"},
		{"Upstream.CargoAPI", cfg.Upstream.CargoAPI, "https://crates.io"},
		{"Upstream.GoMod", cfg.Upstream.GoMod, "https://proxy.golang.org"},
		{"Proxy.BaseURL", cfg.Proxy.BaseURL, "http://localhost:8080"},
		{"Proxy.NPMBaseURL", cfg.Proxy.NPMBaseURL, "http://localhost:8080"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("ADMIN_PORT", "9091")
	t.Setenv("DATABASE_URL", ":memory:")
	t.Setenv("REDIS_ADDR", "redis:6379")
	t.Setenv("REDIS_PASSWORD", "secret")
	t.Setenv("REDIS_DB", "2")
	t.Setenv("UPSTREAM_NPM", "https://npm.example.com")
	t.Setenv("UPSTREAM_COMPOSER", "https://packagist.example.com")
	t.Setenv("UPSTREAM_MAVEN", "https://maven.example.com/repo")
	t.Setenv("UPSTREAM_NUGET", "https://nuget.example.com/v3/index.json")
	t.Setenv("UPSTREAM_CARGO_INDEX", "https://cargo-index.example.com")
	t.Setenv("UPSTREAM_CARGO_API", "https://cargo-api.example.com")
	t.Setenv("UPSTREAM_GOMOD", "https://gomod.example.com")
	t.Setenv("PROXY_BASE_URL", "https://proxy.example.com")
	t.Setenv("PROXY_NPM_BASE_URL", "https://legacy-proxy.example.com")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Port: got %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.AdminPort != 9091 {
		t.Errorf("AdminPort: got %d, want 9091", cfg.Server.AdminPort)
	}
	if cfg.DB.DSN != ":memory:" {
		t.Errorf("DB.DSN: got %q", cfg.DB.DSN)
	}
	if cfg.Redis.Addr != "redis:6379" {
		t.Errorf("Redis.Addr: got %q", cfg.Redis.Addr)
	}
	if cfg.Redis.Password != "secret" {
		t.Errorf("Redis.Password: got %q", cfg.Redis.Password)
	}
	if cfg.Redis.DB != 2 {
		t.Errorf("Redis.DB: got %d, want 2", cfg.Redis.DB)
	}
	if cfg.Upstream.NPM != "https://npm.example.com" {
		t.Errorf("Upstream.NPM: got %q", cfg.Upstream.NPM)
	}
	if cfg.Upstream.Composer != "https://packagist.example.com" {
		t.Errorf("Upstream.Composer: got %q", cfg.Upstream.Composer)
	}
	if cfg.Upstream.Maven != "https://maven.example.com/repo" {
		t.Errorf("Upstream.Maven: got %q", cfg.Upstream.Maven)
	}
	if cfg.Upstream.NuGet != "https://nuget.example.com/v3/index.json" {
		t.Errorf("Upstream.NuGet: got %q", cfg.Upstream.NuGet)
	}
	if cfg.Upstream.CargoIndex != "https://cargo-index.example.com" {
		t.Errorf("Upstream.CargoIndex: got %q", cfg.Upstream.CargoIndex)
	}
	if cfg.Upstream.CargoAPI != "https://cargo-api.example.com" {
		t.Errorf("Upstream.CargoAPI: got %q", cfg.Upstream.CargoAPI)
	}
	if cfg.Upstream.GoMod != "https://gomod.example.com" {
		t.Errorf("Upstream.GoMod: got %q", cfg.Upstream.GoMod)
	}
	if cfg.Proxy.BaseURL != "https://proxy.example.com" {
		t.Errorf("Proxy.BaseURL: got %q", cfg.Proxy.BaseURL)
	}
	if cfg.Proxy.NPMBaseURL != "https://proxy.example.com" {
		t.Errorf("Proxy.NPMBaseURL: got %q", cfg.Proxy.NPMBaseURL)
	}
}

func TestLoad_ProxyNPMBaseURLFallback(t *testing.T) {
	t.Setenv("PROXY_BASE_URL", "")
	t.Setenv("PROXY_NPM_BASE_URL", "https://legacy-proxy.example.com")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.BaseURL != "https://legacy-proxy.example.com" {
		t.Errorf("Proxy.BaseURL: got %q", cfg.Proxy.BaseURL)
	}
	if cfg.Proxy.NPMBaseURL != "https://legacy-proxy.example.com" {
		t.Errorf("Proxy.NPMBaseURL: got %q", cfg.Proxy.NPMBaseURL)
	}
}

func TestLoad_InvalidPort_FallsBackToDefault(t *testing.T) {
	t.Setenv("PORT", "not-a-number")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Port: got %d, want default 8080 for invalid value", cfg.Server.Port)
	}
}
