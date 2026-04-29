package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	npmadapter "github.com/pirikara/registry-gate/internal/adapter/npm"
	pypiadapter "github.com/pirikara/registry-gate/internal/adapter/pypi"
	brewadapter "github.com/pirikara/registry-gate/internal/adapter/homebrew"
	dockeradapter "github.com/pirikara/registry-gate/internal/adapter/docker"
	gemsadapter "github.com/pirikara/registry-gate/internal/adapter/rubygems"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/config"
	"github.com/pirikara/registry-gate/internal/db"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policyfile"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	database, err := db.Open(cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	if database != nil {
		defer database.Close()
		if err := db.Migrate(database); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	recorder := buildRecorder(logger, database)

	var appCache cache.Cache
	if cfg.Redis.Addr != "" {
		appCache = cache.NewRedis(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
		logger.Info("cache: redis", "addr", cfg.Redis.Addr)
	} else {
		appCache = cache.NewMemoryCache()
		logger.Info("cache: in-memory")
	}

	policyFile := envStr("POLICY_FILE", "")
	loaded, err := policyfile.LoadFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if len(loaded.Entries) == 0 {
		logger.Warn("no policy rules loaded — all requests will be allowed", "policy_file", policyFile)
	} else {
		logger.Info("policy rules loaded", "count", len(loaded.Entries), "source", loaded.Source)
	}
	eng := policy.NewEngine(loaded.Entries)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger(logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		if database != nil {
			if err := database.PingContext(context.Background()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	})

	npmAdp := npmadapter.NewAdapter(npmadapter.Config{
		UpstreamURL: cfg.Upstream.NPM,
		ProxyBase:   cfg.Proxy.NPMBaseURL,
		PolicyEng:   eng,
		Recorder:    recorder,
		Cache:       appCache,
		Logger:      logger,
	})

	pypiAdp := pypiadapter.NewAdapter(pypiadapter.Config{
		UpstreamURL: cfg.Upstream.PyPI,
		ProxyBase:   cfg.Proxy.NPMBaseURL,
		PolicyEng:   eng,
		Recorder:    recorder,
		Cache:       appCache,
		Logger:      logger,
	})

	brewAdp := brewadapter.NewAdapter(brewadapter.Config{
		UpstreamURL: cfg.Upstream.Brew,
		PolicyEng:   eng,
		Recorder:    recorder,
		Cache:       appCache,
		Logger:      logger,
	})

	dockerAdp := dockeradapter.NewAdapter(dockeradapter.Config{
		UpstreamURL: cfg.Upstream.Docker,
		PolicyEng:   eng,
		Recorder:    recorder,
		Cache:       appCache,
		Logger:      logger,
	})

	gemsAdp := gemsadapter.NewAdapter(gemsadapter.Config{
		UpstreamURL: cfg.Upstream.Gems,
		PolicyEng:   eng,
		Recorder:    recorder,
		Cache:       appCache,
		Logger:      logger,
	})

	r.Group(func(r chi.Router) {
		pypiAdp.Mount(r)
		npmAdp.Mount(r)
		brewAdp.Mount(r)
		dockerAdp.Mount(r)
		gemsAdp.Mount(r)
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("proxy server starting", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
		}
	}()

	<-quit
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// buildRecorder returns a LogRecorder always, chained with a DBRecorder when db is non-nil.
func buildRecorder(logger *slog.Logger, database *sql.DB) history.Recorder {
	logRec := history.NewLogRecorder(logger)
	if database == nil {
		return logRec
	}
	return history.MultiRecorder{logRec, history.NewRecorder(database)}
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.InfoContext(r.Context(), "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
