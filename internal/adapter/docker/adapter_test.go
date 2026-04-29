package docker_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	dockeradapter "github.com/pirikara/registry-gate/internal/adapter/docker"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

// buildUpstream creates a fake Docker Registry v2 server.
func buildUpstream(manifest *dockeradapter.Manifest) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/v2/":
			w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))

		case strings.Contains(path, "/manifests/"):
			w.Header().Set("Content-Type", dockeradapter.MediaTypeManifestV2)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(manifest)

		case strings.Contains(path, "/blobs/"):
			// Blobs are redirected, so just return OK for HEAD.
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func makeManifest(createdAt time.Time, withSLSA bool) *dockeradapter.Manifest {
	annotations := map[string]string{
		"org.opencontainers.image.created": createdAt.Format(time.RFC3339),
		"org.opencontainers.image.source":  "https://github.com/example/image",
	}
	if withSLSA {
		annotations["in-toto.io/predicate-type"] = "https://slsa.dev/provenance/v1"
	}
	return &dockeradapter.Manifest{
		SchemaVersion: 2,
		MediaType:     dockeradapter.MediaTypeManifestV2,
		Config: dockeradapter.Descriptor{
			MediaType: "application/vnd.docker.container.image.v1+json",
			Digest:    "sha256:abc123",
			Size:      1234,
		},
		Annotations: annotations,
	}
}

func buildAdapter(upstream *httptest.Server, eng *policy.Engine) *dockeradapter.Adapter {
	return dockeradapter.NewTestAdapter(dockeradapter.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   eng,
		Recorder:    history.NewNoopRecorder(),
		Cache:       cache.NoopCache{},
	})
}

func openEng() *policy.Engine {
	return policy.NewEngine(nil)
}

func newProxy(adp *dockeradapter.Adapter) *httptest.Server {
	r := chi.NewRouter()
	adp.Mount(r)
	return httptest.NewServer(r)
}

// --- Version check ---

func TestDocker_VersionCheck(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	proxy := newProxy(buildAdapter(upstream, openEng()))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Docker-Distribution-Api-Version") != "registry/2.0" {
		t.Error("missing Docker-Distribution-Api-Version header")
	}
}

// --- Manifest proxy ---

func TestDocker_Manifest_Allowed(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	proxy := newProxy(buildAdapter(upstream, openEng()))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/library/ubuntu/manifests/22.04")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "manifest") {
		t.Errorf("expected manifest content-type, got %s", ct)
	}
}

func TestDocker_Manifest_BlockedByCooldown(t *testing.T) {
	// Image published 1 day ago, cooldown requires 7 days.
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -1), false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	proxy := newProxy(buildAdapter(upstream, eng))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/newimage/app/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	// Docker error format: {"errors":[{"code":"DENIED",...}]}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if _, ok := body["errors"]; !ok {
		t.Error("expected Docker error JSON format")
	}
}

func TestDocker_Manifest_BlockedByDenyList(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewDeny("deny", []policy.PackageRef{
			{Ecosystem: facts.EcosystemDocker, Name: "evil/image"},
		}),
	}})

	proxy := newProxy(buildAdapter(upstream, eng))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/evil/image/manifests/latest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// --- Blob redirect ---

func TestDocker_Blob_Redirect(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	proxy := newProxy(buildAdapter(upstream, openEng()))
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/v2/library/ubuntu/blobs/sha256:abc123def")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for blob, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "blobs/sha256:abc123def") {
		t.Errorf("redirect location should contain blob digest, got: %s", loc)
	}
}

// --- Scoped image name (multi-segment) ---

func TestDocker_Manifest_ScopedImageName(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	proxy := newProxy(buildAdapter(upstream, openEng()))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/myorg/sub/image/manifests/v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Should get a 200 from our mock upstream.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for multi-segment image name, got %d", resp.StatusCode)
	}
}

// --- Trust downgrade ---
//
// Docker manifest responses describe a single image:tag, not the package's
// version history, so the adapter cannot compute an inline baseline like the
// npm adapter does. With no baseline available, trust_downgrade falls through
// to its on_unknown handler — verify that on_unknown=block produces a 403.
func TestDocker_Manifest_TrustDowngrade_NoBaseline_Block(t *testing.T) {
	upstream := buildUpstream(makeManifest(time.Now().AddDate(0, 0, -30), false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade("td",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownBlock,
		),
	}})

	proxy := newProxy(buildAdapter(upstream, eng))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/v2/myorg/app/manifests/2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 with on_unknown=block, got %d", resp.StatusCode)
	}
}
