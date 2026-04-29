package principal_test

import (
	"net/http"
	"testing"

	"github.com/pirikara/registory-gate/internal/adapter/principal"
)

func TestLabel_NoHeaders(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	if got := principal.Label(r); got != "" {
		t.Errorf("got %q, want empty string for unauthenticated request", got)
	}
}

func TestLabel_XForwardedUser(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-User", "alice")
	if got := principal.Label(r); got != "alice" {
		t.Errorf("got %q, want 'alice'", got)
	}
}

func TestLabel_XAuthRequestUser(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Auth-Request-User", "bob")
	if got := principal.Label(r); got != "bob" {
		t.Errorf("got %q, want 'bob'", got)
	}
}

func TestLabel_XForwardedEmail(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-Email", "carol@example.com")
	if got := principal.Label(r); got != "carol@example.com" {
		t.Errorf("got %q, want 'carol@example.com'", got)
	}
}

func TestLabel_Priority_FirstHeaderWins(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-User", "first")
	r.Header.Set("X-Auth-Request-User", "second")
	r.Header.Set("X-Forwarded-Email", "third@example.com")
	if got := principal.Label(r); got != "first" {
		t.Errorf("got %q, want 'first' (X-Forwarded-User has highest priority)", got)
	}
}

func TestLabel_FallsThrough_WhenLeadingHeaderEmpty(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set("X-Auth-Request-User", "fallback")
	if got := principal.Label(r); got != "fallback" {
		t.Errorf("got %q, want 'fallback'", got)
	}
}
