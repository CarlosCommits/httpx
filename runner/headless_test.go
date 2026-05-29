package runner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func TestHasReactBundleEvidence(t *testing.T) {
	scriptBodies := []string{
		`/*! @license react */` + "\n" + `/* react-dom.production.min.js */`,
	}

	if !hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected React bundle evidence to be detected")
	}
}

func TestHasReactBundleEvidenceRequiresReactPackageMarker(t *testing.T) {
	scriptBodies := []string{
		`/*! @license react */`,
	}

	if hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected partial React evidence to be ignored")
	}
}

func TestHasReactBundleEvidenceFromRuntimeSymbols(t *testing.T) {
	scriptBodies := []string{
		`var p=symbol.for("react.transitional.element"),r=symbol.for("react.portal"),e=symbol.for("react.fragment"),y=symbol.for("react.strict_mode"),p=symbol.for("react.profiler"),w=symbol.for("react.consumer"),m=symbol.for("react.context"),t=symbol.for("react.forward_ref"),i=symbol.for("react.suspense"),t=symbol.for("react.memo"),c=symbol.for("react.lazy");`,
	}

	if !hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected React runtime symbol evidence to be detected")
	}
}

func TestHasReactBundleEvidenceFromBacktickRuntimeSymbols(t *testing.T) {
	scriptBodies := []string{
		"var p=symbol.for(`react.transitional.element`),r=symbol.for(`react.portal`),e=symbol.for(`react.fragment`),y=symbol.for(`react.strict_mode`),p=symbol.for(`react.profiler`),w=symbol.for(`react.consumer`),m=symbol.for(`react.context`),t=symbol.for(`react.forward_ref`),i=symbol.for(`react.suspense`),t=symbol.for(`react.memo`),c=symbol.for(`react.lazy`);",
	}

	if !hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected React runtime symbol evidence with template literals to be detected")
	}
}

func TestRuntimeBundleTechnologiesAddsReactFromBacktickRuntimeSymbols(t *testing.T) {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("expected wappalyzer client to initialize: %v", err)
	}

	technologies := map[string]wappalyzer.AppInfo{}
	scriptBodies := []string{
		"var p=symbol.for(`react.transitional.element`),r=symbol.for(`react.portal`),e=symbol.for(`react.fragment`),y=symbol.for(`react.strict_mode`),p=symbol.for(`react.profiler`),w=symbol.for(`react.consumer`),m=symbol.for(`react.context`),t=symbol.for(`react.forward_ref`),i=symbol.for(`react.suspense`),t=symbol.for(`react.memo`),c=symbol.for(`react.lazy`);",
	}

	addRuntimeBundleTechnologies(technologies, wappalyzerClient, wappalyzerClient.GetFingerprints(), "", nil, scriptBodies)

	if _, ok := technologies["React"]; !ok {
		t.Fatal("expected React to be added from runtime bundle evidence")
	}
}

func TestRuntimeBundleTechnologiesAddsCustomTanStackTechnologies(t *testing.T) {
	wappalyzerClient := newTestCustomWappalyzerClient(t)
	technologies := map[string]wappalyzer.AppInfo{}
	pageBody := `window.__TSR={};$_TSR.router={};<script id="tsr-scroll-restoration-v1_3"></script><script id="tsr-stream-barrier"></script>`
	scriptBodies := []string{`/*! @tanstack/react-query */ import "@tanstack/query-core";`}

	addRuntimeBundleTechnologies(technologies, wappalyzerClient, wappalyzerClient.GetFingerprints(), pageBody, nil, scriptBodies)

	for _, name := range []string{"TanStack Router", "TanStack Start", "TanStack Query"} {
		if _, ok := technologies[name]; !ok {
			t.Fatalf("expected %s to be added from custom TanStack evidence", name)
		}
	}
}

func TestHasReactBundleEvidenceRequiresMultipleRuntimeSymbols(t *testing.T) {
	scriptBodies := []string{
		`const label = Symbol.for("react.fragment");`,
	}

	if hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected partial React runtime symbol evidence to be ignored")
	}
}

func TestHasTanStackRouterBundleEvidence(t *testing.T) {
	body := `$_TSR.router={manifest:{}};<script id="tsr-scroll-restoration-v1_3"></script>`

	if !hasTanStackRouterBundleEvidence(body, nil) {
		t.Fatal("expected TanStack Router bundle evidence to be detected")
	}
}

func TestHasTanStackStartBundleEvidenceRequiresStreamBarrier(t *testing.T) {
	routerOnlyBody := `$_TSR.router={manifest:{}};<script id="tsr-scroll-restoration-v1_3"></script>`
	startBody := `$_TSR.router={manifest:{}};<script id="tsr-stream-barrier"></script>`

	if hasTanStackStartBundleEvidence(routerOnlyBody, nil) {
		t.Fatal("expected router-only evidence not to imply TanStack Start")
	}
	if !hasTanStackStartBundleEvidence(startBody, nil) {
		t.Fatal("expected TanStack Start stream evidence to be detected")
	}
}

func TestHasTanStackQueryBundleEvidenceRequiresPackageMarker(t *testing.T) {
	if hasTanStackQueryBundleEvidence([]string{`const queryClient = {}; const dehydrated = {};`}) {
		t.Fatal("expected generic query words not to imply TanStack Query")
	}
	if !hasTanStackQueryBundleEvidence([]string{`import "@tanstack/query-core";`}) {
		t.Fatal("expected TanStack Query package marker to be detected")
	}
}

func TestHasViteBundleEvidenceFromDataVite(t *testing.T) {
	body := `<style data-vite-theme="" data-inject-first=""></style>`

	if !hasViteBundleEvidence(body, nil, nil) {
		t.Fatal("expected data-vite attribute to be detected")
	}
}

func newTestCustomWappalyzerClient(t *testing.T) *wappalyzer.Wappalyze {
	t.Helper()

	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "TanStack Router": {
      "cats": [12],
      "description": "TanStack Router"
    },
    "TanStack Start": {
      "cats": [18, 12],
      "description": "TanStack Start"
    },
    "TanStack Query": {
      "cats": [59],
      "description": "TanStack Query"
    }
  }
}`)

	wappalyzerClient, err := newWappalyzerClient(fingerprintPath)
	if err != nil {
		t.Fatalf("expected custom wappalyzer client to initialize: %v", err)
	}

	return wappalyzerClient
}

func TestHasViteBundleEvidenceFromModuleAssets(t *testing.T) {
	body := `<script type="module" crossorigin src="/assets/index-DyXVzQOV.js"></script>` +
		`<link rel="stylesheet" crossorigin href="/assets/index-CWP6jorY.css">`
	scriptBodies := []string{`const scriptRel = "modulepreload";`}

	if !hasViteBundleEvidence(body, nil, scriptBodies) {
		t.Fatal("expected Vite module asset evidence to be detected")
	}
}

func TestHasViteBundleEvidenceRequiresMultipleSignals(t *testing.T) {
	body := `<script type="module" crossorigin src="/assets/index-DyXVzQOV.js"></script>`

	if hasViteBundleEvidence(body, nil, nil) {
		t.Fatal("expected lone module asset to be ignored")
	}
}

func TestSameOriginScriptCandidatesIncludesStartedRequests(t *testing.T) {
	body := `<script type="module" crossorigin src="/assets/index-DyXVzQOV.js"></script>`
	requests := []NetworkRequest{
		{URL: "https://example.com/assets/late.js", ResourceType: "Script", StatusCode: -1},
		{URL: "https://cdn.example.net/vendor.js", ResourceType: "Script", StatusCode: 200},
	}

	got := sameOriginScriptCandidates(body, requests, "https://example.com")

	want := map[string]bool{
		"https://example.com/assets/index-DyXVzQOV.js": false,
		"https://example.com/assets/late.js":           false,
	}
	for _, candidate := range got {
		if _, ok := want[candidate]; ok {
			want[candidate] = true
		}
		if candidate == "https://cdn.example.net/vendor.js" {
			t.Fatal("expected third-party script to be excluded")
		}
	}
	for candidate, found := range want {
		if !found {
			t.Fatalf("expected candidate %s", candidate)
		}
	}
}

func TestSameOriginScriptCandidatesIncludesModulePreloadsAndDynamicImports(t *testing.T) {
	body := `<link rel="modulepreload" href="/assets/link-BwGhZYyD.js">` +
		`<script type="module" async>import("/assets/index-BSK55Tcu.js")</script>`

	got := sameOriginScriptCandidates(body, nil, "https://example.com")

	want := map[string]bool{
		"https://example.com/assets/link-BwGhZYyD.js":  false,
		"https://example.com/assets/index-BSK55Tcu.js": false,
	}
	for _, candidate := range got {
		if _, ok := want[candidate]; ok {
			want[candidate] = true
		}
	}
	for candidate, found := range want {
		if !found {
			t.Fatalf("expected candidate %s in %v", candidate, got)
		}
	}
}

func TestFetchSameOriginScriptBodiesUsesBoundedConcurrency(t *testing.T) {
	const scriptCount = 6

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = fmt.Fprintf(w, `console.log("script %s");`, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	body := ""
	for i := 0; i < scriptCount; i++ {
		body += fmt.Sprintf(`<script src="/assets/script-%d.js"></script>`, i)
	}

	startedAt := time.Now()
	collection := fetchSameOriginScriptBodies(body, nil, server.URL, map[string]struct{}{})
	elapsed := time.Since(startedAt)

	if len(collection.Bodies) != scriptCount {
		t.Fatalf("expected %d fallback script bodies, got %d", scriptCount, len(collection.Bodies))
	}
	if len(collection.CapturedURLs) != scriptCount {
		t.Fatalf("expected %d captured fallback URLs, got %d", scriptCount, len(collection.CapturedURLs))
	}
	if collection.Bytes == 0 {
		t.Fatal("expected fallback script bytes to be recorded")
	}
	if elapsed > 1400*time.Millisecond {
		t.Fatalf("expected fallback script fetches to run concurrently, took %s", elapsed)
	}
}

func TestReadinessAllowsOnlyThirdPartyChallengePending(t *testing.T) {
	requests := []NetworkRequest{
		{URL: "https://example.com/assets/index.js", ResourceType: "Script", StatusCode: 200},
		{URL: "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/test", ResourceType: "XHR", StatusCode: -1},
	}

	if !onlyThirdPartyChallengeRequestsPending(requests, "https://example.com") {
		t.Fatal("expected Cloudflare challenge request to be treated as non-blocking")
	}
}

func TestReadinessBlocksOnPendingSameOriginScript(t *testing.T) {
	requests := []NetworkRequest{
		{URL: "https://example.com/assets/index.js", ResourceType: "Script", StatusCode: -1},
	}

	if !hasPendingSameOriginScripts(requests, "https://example.com") {
		t.Fatal("expected pending same-origin script to block readiness")
	}
	if onlyThirdPartyChallengeRequestsPending(requests, "https://example.com") {
		t.Fatal("expected pending same-origin script to remain blocking")
	}
}

func TestReadinessStopsForQuietPageWithFallbackScriptCandidates(t *testing.T) {
	requests := []NetworkRequest{
		{URL: "https://example.com/assets/index.js", ResourceType: "Script", StatusCode: 0},
		{URL: "https://analytics.example.net/beacon", ResourceType: "Fetch", StatusCode: -1},
	}
	scriptCandidates := []string{"https://example.com/assets/index.js"}

	if !shouldStopHeadlessReadiness(requests, scriptCandidates, "https://example.com", false) {
		t.Fatal("expected quiet page with script candidates to proceed to fallback collection")
	}
}

func TestReadinessDoesNotStopForQuietPageWithoutRuntimeEvidence(t *testing.T) {
	requests := []NetworkRequest{
		{URL: "https://example.com/api/state", ResourceType: "Fetch", StatusCode: 200},
	}

	if shouldStopHeadlessReadiness(requests, nil, "https://example.com", false) {
		t.Fatal("expected quiet page without script candidates or hydrated app evidence to keep waiting")
	}
}

func TestMatchHeaderFingerprintUsesSameOriginBrowserHeaders(t *testing.T) {
	requests := []NetworkRequest{
		{
			URL:             "https://example.com/api/status",
			StatusCode:      200,
			ResponseHeaders: map[string]string{"x-powered-by": "express"},
		},
	}
	fingerprint := &wappalyzer.Fingerprint{
		Headers: map[string]string{"x-powered-by": "express"},
	}

	matched, _ := (&Browser{}).matchHeaderFingerprint(fingerprint, requests, "https://example.com")
	if !matched {
		t.Fatal("expected same-origin browser response header to match")
	}
}

func TestMatchHeaderFingerprintIgnoresThirdPartyBrowserHeaders(t *testing.T) {
	requests := []NetworkRequest{
		{
			URL:             "https://third-party.example/api/status",
			StatusCode:      200,
			ResponseHeaders: map[string]string{"x-powered-by": "express"},
		},
	}
	fingerprint := &wappalyzer.Fingerprint{
		Headers: map[string]string{"x-powered-by": "express"},
	}

	matched, _ := (&Browser{}).matchHeaderFingerprint(fingerprint, requests, "https://example.com")
	if matched {
		t.Fatal("expected third-party browser response header to be ignored")
	}
}
