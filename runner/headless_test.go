package runner

import (
	"testing"

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

func TestHasReactBundleEvidenceRequiresMultipleRuntimeSymbols(t *testing.T) {
	scriptBodies := []string{
		`const label = Symbol.for("react.fragment");`,
	}

	if hasReactBundleEvidence(scriptBodies) {
		t.Fatal("expected partial React runtime symbol evidence to be ignored")
	}
}

func TestHasViteBundleEvidenceFromDataVite(t *testing.T) {
	body := `<style data-vite-theme="" data-inject-first=""></style>`

	if !hasViteBundleEvidence(body, nil, nil) {
		t.Fatal("expected data-vite attribute to be detected")
	}
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
