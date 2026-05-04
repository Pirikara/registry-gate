package main

import (
	"context"
	"encoding/json"
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

	"github.com/pirikara/registry-gate/internal/config"
	"github.com/pirikara/registry-gate/internal/db"
	"github.com/pirikara/registry-gate/internal/facts"
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

	policyFile := envStr("POLICY_FILE", "")
	loaded, err := policyfile.LoadFromFile(policyFile)
	if err != nil {
		logger.Warn("failed to load policy file", "path", policyFile, "err", err)
		loaded = &policyfile.Loaded{}
	}

	var querier *history.Querier
	if database != nil {
		querier = history.NewQuerier(database)
	}

	allowOrigin := envStr("CORS_ALLOW_ORIGIN", "*")

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/policy", handleGetPolicy(loaded))
		r.Get("/downloads", handleListDownloads(querier))
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.AdminPort),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("admin server starting", "addr", srv.Addr, "policy_file", policyFile)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
		}
	}()

	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

func handleGetPolicy(loaded *policyfile.Loaded) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		view := struct {
			Source  string     `json:"source"`
			Version int        `json:"version"`
			Rules   []ruleView `json:"rules"`
		}{
			Source:  loaded.Source,
			Version: loaded.Version,
		}
		for _, e := range loaded.Entries {
			view.Rules = append(view.Rules, toRuleView(e))
		}
		writeJSON(w, http.StatusOK, view)
	}
}

type ruleView struct {
	ID                     string   `json:"id"`
	Ecosystems             []string `json:"ecosystems,omitempty"`
	Packages               []string `json:"packages,omitempty"`
	PackagePatterns        []string `json:"packagePatterns,omitempty"`
	ExcludePackagePatterns []string `json:"excludePackagePatterns,omitempty"`
}

func toRuleView(e policy.Entry) ruleView {
	rv := ruleView{ID: e.Rule.ID()}
	for _, eco := range e.Match.Ecosystems {
		rv.Ecosystems = append(rv.Ecosystems, string(eco))
	}
	for _, p := range e.Match.Packages {
		rv.Packages = append(rv.Packages, string(p.Ecosystem)+":"+p.Name)
	}
	for _, p := range e.Match.PackagePatterns {
		rv.PackagePatterns = append(rv.PackagePatterns, string(p.Ecosystem)+":"+p.Pattern)
	}
	for _, p := range e.Match.ExcludePackagePatterns {
		rv.ExcludePackagePatterns = append(rv.ExcludePackagePatterns, string(p.Ecosystem)+":"+p.Pattern)
	}
	return rv
}

func handleListDownloads(q *history.Querier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if q == nil {
			writeJSON(w, http.StatusOK, map[string]any{"records": []any{}, "count": 0, "note": "DATABASE_URL not configured"})
			return
		}
		qs := r.URL.Query()
		f := history.Filter{
			Ecosystem:   facts.Ecosystem(qs.Get("ecosystem")),
			PackageName: qs.Get("package"),
			Outcome:     history.Outcome(qs.Get("outcome")),
		}
		if v := qs.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.From = t
			}
		}
		if v := qs.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.To = t
			}
		}

		records, err := q.List(r.Context(), f)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": records, "count": len(records)})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
