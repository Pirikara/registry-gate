package e2e_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	gomodadapter "github.com/pirikara/registry-gate/internal/adapter/gomod"
	npmadapter "github.com/pirikara/registry-gate/internal/adapter/npm"
	gemsadapter "github.com/pirikara/registry-gate/internal/adapter/rubygems"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

const (
	e2eEnv = "REGISTRY_GATE_CLIENT_E2E"

	npmFixtureName = "registrygate-fixture-pkg"
	npmFixtureVer  = "1.0.0"

	goFixtureModule = "example.invalid/registrygate/fixture"
	goFixtureVer    = "v1.0.0"

	gemFixtureName = "registrygate_fixture_gem"
	gemFixtureVer  = "1.0.0"
)

func TestClientE2E_GoModDownload(t *testing.T) {
	requireClientE2E(t, "go")

	upstream := httptest.NewServer(goProxyUpstream(t))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	gomodadapter.NewTestAdapter(gomodadapter.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   policy.NewEngine(nil),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	work := t.TempDir()
	runCmd(t, work, []string{
		"GOPROXY=" + proxy.URL + "/gomod",
		"GOSUMDB=off",
		"GOMODCACHE=" + goModCache(t),
	}, "go", "mod", "download", goFixtureModule+"@"+goFixtureVer)
}

func TestClientE2E_GoModDownloadBlocked(t *testing.T) {
	requireClientE2E(t, "go")

	upstream := httptest.NewServer(goProxyUpstream(t))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	gomodadapter.NewTestAdapter(gomodadapter.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   denyEngine(facts.EcosystemGoMod, goFixtureModule),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	work := t.TempDir()
	out, err := runCmdErr(work, []string{
		"GOPROXY=" + proxy.URL + "/gomod",
		"GOSUMDB=off",
		"GOMODCACHE=" + goModCache(t),
	}, "go", "mod", "download", goFixtureModule+"@"+goFixtureVer)
	if err == nil {
		t.Fatalf("expected blocked go mod download to fail; output:\n%s", out)
	}
	if !strings.Contains(out, "403") {
		t.Fatalf("expected go output to mention 403; output:\n%s", out)
	}
}

func TestClientE2E_NPMInstall(t *testing.T) {
	requireClientE2E(t, "npm")

	tarball := makeNPMTarball(t, npmFixtureName, npmFixtureVer)
	upstream := httptest.NewServer(npmUpstream(t, tarball))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	npmadapter.NewTestAdapter(npmadapter.Config{
		UpstreamURL:      upstream.URL,
		ProxyBase:        proxy.URL,
		DownloadsAPIBase: upstream.URL,
		PolicyEng:        policy.NewEngine(nil),
		Recorder:         history.NewNoopRecorder(),
	}).Mount(r)

	work := t.TempDir()
	writeFile(t, filepath.Join(work, "package.json"), []byte(`{"private":true}`))
	runCmd(t, work, npmEnv(t),
		"npm", "install",
		"--registry", proxy.URL,
		"--cache", filepath.Join(t.TempDir(), "npm-cache"),
		"--ignore-scripts",
		"--no-audit",
		"--fund=false",
		npmFixtureName+"@"+npmFixtureVer,
	)

	if _, err := os.Stat(filepath.Join(work, "node_modules", npmFixtureName, "package.json")); err != nil {
		t.Fatalf("expected npm package to be installed: %v", err)
	}
}

func TestClientE2E_NPMInstallBlocked(t *testing.T) {
	requireClientE2E(t, "npm")

	tarball := makeNPMTarball(t, npmFixtureName, npmFixtureVer)
	upstream := httptest.NewServer(npmUpstream(t, tarball))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	npmadapter.NewTestAdapter(npmadapter.Config{
		UpstreamURL:      upstream.URL,
		ProxyBase:        proxy.URL,
		DownloadsAPIBase: upstream.URL,
		PolicyEng:        denyEngine(facts.EcosystemNPM, npmFixtureName),
		Recorder:         history.NewNoopRecorder(),
	}).Mount(r)

	work := t.TempDir()
	writeFile(t, filepath.Join(work, "package.json"), []byte(`{"private":true}`))
	out, err := runCmdErr(work, npmEnv(t),
		"npm", "install",
		"--registry", proxy.URL,
		"--cache", filepath.Join(t.TempDir(), "npm-cache"),
		"--ignore-scripts",
		"--no-audit",
		"--fund=false",
		npmFixtureName+"@"+npmFixtureVer,
	)
	if err == nil {
		t.Fatalf("expected blocked npm install to fail; output:\n%s", out)
	}
	if !strings.Contains(out, "403") {
		t.Fatalf("expected npm output to mention 403; output:\n%s", out)
	}
}

func TestClientE2E_GemInstallFromProxySource(t *testing.T) {
	requireClientE2E(t, "gem", "ruby")

	fixture := buildGemFixture(t)
	upstream := httptest.NewServer(rubygemsUpstream(t, fixture))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	gemsadapter.NewTestAdapter(gemsadapter.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   policy.NewEngine(nil),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	installDir := filepath.Join(t.TempDir(), "gems")
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".gemrc"), []byte(":sources:\n- "+proxy.URL+"\n"))
	runCmd(t, t.TempDir(), []string{
		"HOME=" + home,
		"GEM_HOME=" + installDir,
		"GEM_PATH=" + installDir,
	}, "gem", "install", "--clear-sources", "--source", proxy.URL, "--no-document", "--ignore-dependencies", "--verbose", "--install-dir", installDir, gemFixtureName, "-v", gemFixtureVer)

	if _, err := os.Stat(filepath.Join(installDir, "gems", gemFixtureName+"-"+gemFixtureVer)); err != nil {
		t.Fatalf("expected gem to be installed: %v", err)
	}
}

func TestClientE2E_GemInstallBlocked(t *testing.T) {
	requireClientE2E(t, "gem", "ruby")

	fixture := buildGemFixture(t)
	upstream := httptest.NewServer(rubygemsUpstream(t, fixture))
	defer upstream.Close()

	r := chi.NewRouter()
	proxy := httptest.NewUnstartedServer(r)
	proxy.Start()
	defer proxy.Close()

	gemsadapter.NewTestAdapter(gemsadapter.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   denyEngine(facts.EcosystemRubyGems, gemFixtureName),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	installDir := filepath.Join(t.TempDir(), "gems")
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".gemrc"), []byte(":sources:\n- "+proxy.URL+"\n"))
	out, err := runCmdErr(t.TempDir(), []string{
		"HOME=" + home,
		"GEM_HOME=" + installDir,
		"GEM_PATH=" + installDir,
	}, "gem", "install", "--clear-sources", "--source", proxy.URL, "--no-document", "--ignore-dependencies", "--verbose", "--install-dir", installDir, gemFixtureName, "-v", gemFixtureVer)
	if err == nil {
		t.Fatalf("expected blocked gem install to fail; output:\n%s", out)
	}
}

func requireClientE2E(t *testing.T, bins ...string) {
	t.Helper()
	if os.Getenv(e2eEnv) != "1" {
		t.Skipf("set %s=1 to run real package-client E2E tests", e2eEnv)
	}
	for _, bin := range bins {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found in PATH", bin)
		}
	}
}

func runCmd(t *testing.T, dir string, extraEnv []string, name string, args ...string) {
	t.Helper()
	out, err := runCmdErr(dir, extraEnv, name, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func runCmdErr(dir string, extraEnv []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), ctx.Err()
	}
	return string(out), err
}

func npmEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	return []string{
		"HOME=" + home,
		"NO_UPDATE_NOTIFIER=1",
		"npm_config_update_notifier=false",
		"npm_config_loglevel=warn",
	}
}

func goModCache(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "registry-gate-gomodcache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
		_ = os.RemoveAll(dir)
	})
	return dir
}

func denyEngine(eco facts.Ecosystem, pkg string) *policy.Engine {
	pattern := policy.PackagePattern{Ecosystem: eco, Pattern: pkg}
	return policy.NewEngine([]policy.Entry{{
		Match: policy.Match{PackagePatterns: []policy.PackagePattern{pattern}},
		Rule:  rules.NewDenyPatterns(string(eco)+"/deny", []policy.PackagePattern{pattern}),
	}})
}

func goProxyUpstream(t *testing.T) http.Handler {
	t.Helper()
	zipBytes := makeGoModuleZip(t, goFixtureModule, goFixtureVer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + goFixtureModule + "/@v/list":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(goFixtureVer + "\n"))
		case "/" + goFixtureModule + "/@v/" + goFixtureVer + ".info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Version":"` + goFixtureVer + `","Time":"2026-01-02T03:04:05Z"}`))
		case "/" + goFixtureModule + "/@v/" + goFixtureVer + ".mod":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("module " + goFixtureModule + "\n\ngo 1.24\n"))
		case "/" + goFixtureModule + "/@v/" + goFixtureVer + ".zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	})
}

func makeGoModuleZip(t *testing.T, modulePath, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	prefix := modulePath + "@" + version + "/"
	addZipFile(t, zw, prefix+"go.mod", "module "+modulePath+"\n\ngo 1.24\n")
	addZipFile(t, zw, prefix+"fixture.go", "package fixture\n\nconst Name = \"registry-gate\"\n")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func npmUpstream(t *testing.T, tarball []byte) http.Handler {
	t.Helper()
	shasum := sha1.Sum(tarball)
	sha512sum := sha512.Sum512(tarball)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + npmFixtureName:
			w.Header().Set("Content-Type", "application/json")
			meta := map[string]any{
				"name": npmFixtureName,
				"dist-tags": map[string]string{
					"latest": npmFixtureVer,
				},
				"time": map[string]string{
					npmFixtureVer: "2026-01-02T03:04:05Z",
				},
				"versions": map[string]any{
					npmFixtureVer: map[string]any{
						"name":    npmFixtureName,
						"version": npmFixtureVer,
						"_npmUser": map[string]string{
							"name":  "registrygate-fixture",
							"email": "registrygate-fixture@example.invalid",
						},
						"dist": map[string]string{
							"tarball":   "https://registry.example.invalid/" + npmFixtureName + "/-/" + npmFixtureName + "-" + npmFixtureVer + ".tgz",
							"shasum":    fmt.Sprintf("%x", shasum),
							"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sha512sum[:]),
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(meta)
		case "/" + npmFixtureName + "/-/" + npmFixtureName + "-" + npmFixtureVer + ".tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(tarball)
		case "/downloads/point/last-month/" + npmFixtureName:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"downloads":42,"package":"` + npmFixtureName + `"}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func makeNPMTarball(t *testing.T, name, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	addTarFile(t, tw, "package/package.json", fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js"}`, name, version))
	addTarFile(t, tw, "package/index.js", "module.exports = 'registry-gate fixture';\n")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type builtGemFixture struct {
	gemFile string
	specRZ  string
}

func rubygemsUpstream(t *testing.T, fixture builtGemFixture) http.Handler {
	t.Helper()
	gemBytes := readFile(t, fixture.gemFile)
	specBytes := readFile(t, fixture.specRZ)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/versions":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("created_at: 2026-01-02T03:04:05Z\n---\n" + gemFixtureName + " " + gemFixtureVer + "\n"))
		case "/info/" + gemFixtureName:
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(gemFixtureVer + "\n"))
		case "/api/v1/versions/" + gemFixtureName + ".json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"number":"` + gemFixtureVer + `","created_at":"2026-01-02T03:04:05Z","authors":"registrygate-fixture","yanked":false,"downloads_count":1,"platform":"ruby","dependencies":[]}]`))
		case "/api/v2/rubygems/" + gemFixtureName + "/versions/" + gemFixtureVer + ".json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"` + gemFixtureName + `","number":"` + gemFixtureVer + `","authors":"registrygate-fixture","version_created_at":"2026-01-02T03:04:05Z","yanked":false,"metadata":{"rubygems_mfa_required":"true"},"dependencies":{}}`))
		case "/quick/Marshal.4.8/" + gemFixtureName + "-" + gemFixtureVer + ".gemspec.rz":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(specBytes)
		case "/gems/" + gemFixtureName + "-" + gemFixtureVer + ".gem":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(gemBytes)
		default:
			http.NotFound(w, r)
		}
	})
}

func buildGemFixture(t *testing.T) builtGemFixture {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, gemFixtureName+".gemspec"), []byte(`Gem::Specification.new do |spec|
  spec.name = "`+gemFixtureName+`"
  spec.version = "`+gemFixtureVer+`"
  spec.summary = "Registry Gate fixture gem"
  spec.authors = ["registrygate-fixture"]
  spec.files = ["lib/`+gemFixtureName+`.rb"]
  spec.require_paths = ["lib"]
end
`))
	writeFile(t, filepath.Join(dir, "lib", gemFixtureName+".rb"), []byte("module RegistrygateFixtureGem\n  VERSION = \"1.0.0\"\nend\n"))
	runCmd(t, dir, nil, "gem", "build", gemFixtureName+".gemspec")
	runCmd(t, dir, nil, "ruby", "-e", `require "rubygems"; require "zlib"; spec = Gem::Specification.load("`+gemFixtureName+`.gemspec"); File.binwrite("`+gemFixtureName+`-`+gemFixtureVer+`.gemspec.rz", Zlib::Deflate.deflate(Marshal.dump(spec)))`)
	return builtGemFixture{
		gemFile: filepath.Join(dir, gemFixtureName+"-"+gemFixtureVer+".gem"),
		specRZ:  filepath.Join(dir, gemFixtureName+"-"+gemFixtureVer+".gemspec.rz"),
	}
}

func addZipFile(t *testing.T, zw *zip.Writer, name, body string) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
}

func addTarFile(t *testing.T, tw *tar.Writer, name, body string) {
	t.Helper()
	data := []byte(body)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o644,
		Size: int64(len(data)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
