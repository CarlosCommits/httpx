package runner

import (
	"os"
	"path/filepath"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func TestCustomFingerprintsMergeWithEmbeddedApps(t *testing.T) {
	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "Stripe": {
      "cats": [41],
      "html": ["custom-stripe-marker"],
      "cookies": {
        "custom_stripe_cookie": ""
      }
    }
  }
}`)

	wappalyzerClient, err := newWappalyzerClient(fingerprintPath)
	if err != nil {
		t.Fatalf("expected merged wappalyzer client to initialize: %v", err)
	}

	upstreamMatches := wappalyzerClient.FingerprintWithInfo(
		map[string][]string{},
		[]byte(`<script src="https://js.stripe.com/v3"></script>`),
	)
	if _, ok := upstreamMatches["Stripe"]; !ok {
		t.Fatal("expected embedded Stripe scriptSrc rule to remain after custom merge")
	}

	customMatches := wappalyzerClient.FingerprintWithInfo(
		map[string][]string{"set-cookie": {"custom_stripe_cookie=1"}},
		[]byte("custom-stripe-marker"),
	)
	if _, ok := customMatches["Stripe"]; !ok {
		t.Fatal("expected custom Stripe rules to be appended to embedded rules")
	}
}

func TestCustomFingerprintsAddNewApps(t *testing.T) {
	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "Example Custom Tech": {
      "cats": [59],
      "html": ["example-custom-tech-marker"]
    }
  }
}`)

	wappalyzerClient, err := newWappalyzerClient(fingerprintPath)
	if err != nil {
		t.Fatalf("expected merged wappalyzer client to initialize: %v", err)
	}

	matches := wappalyzerClient.FingerprintWithInfo(
		map[string][]string{},
		[]byte("example-custom-tech-marker"),
	)
	if _, ok := matches["Example Custom Tech"]; !ok {
		t.Fatal("expected new custom app to be detected")
	}
}

func TestMergeFingerprintCombinesRuleShapes(t *testing.T) {
	base := &wappalyzer.Fingerprint{
		Cats:      []int{41},
		HTML:      []string{"upstream-html"},
		ScriptSrc: []string{"upstream-script"},
		Cookies:   map[string]string{"upstream_cookie": ""},
		Headers:   map[string]string{"server": "upstream"},
		Meta:      map[string][]string{"generator": {"upstream-meta"}},
		Dom: map[string]map[string]interface{}{
			"style[data-upstream]": {"exists": ""},
		},
		Description: "upstream description",
	}
	custom := &wappalyzer.Fingerprint{
		Cats:      []int{41, 59},
		HTML:      []string{"upstream-html", "custom-html"},
		ScriptSrc: []string{"custom-script"},
		Cookies:   map[string]string{"custom_cookie": ""},
		Headers:   map[string]string{"x-custom": "custom"},
		Meta:      map[string][]string{"generator": {"custom-meta"}},
		Dom: map[string]map[string]interface{}{
			"style[data-custom]": {"exists": ""},
		},
		Description: "custom description",
	}

	mergeFingerprint(base, custom)

	if len(base.Cats) != 2 {
		t.Fatalf("expected categories to be appended uniquely, got %v", base.Cats)
	}
	assertStringSliceContains(t, base.HTML, "upstream-html")
	assertStringSliceContains(t, base.HTML, "custom-html")
	assertStringSliceContains(t, base.ScriptSrc, "upstream-script")
	assertStringSliceContains(t, base.ScriptSrc, "custom-script")
	if _, ok := base.Cookies["upstream_cookie"]; !ok {
		t.Fatal("expected upstream cookie rule to remain")
	}
	if _, ok := base.Cookies["custom_cookie"]; !ok {
		t.Fatal("expected custom cookie rule to be added")
	}
	if _, ok := base.Headers["server"]; !ok {
		t.Fatal("expected upstream header rule to remain")
	}
	if _, ok := base.Headers["x-custom"]; !ok {
		t.Fatal("expected custom header rule to be added")
	}
	assertStringSliceContains(t, base.Meta["generator"], "upstream-meta")
	assertStringSliceContains(t, base.Meta["generator"], "custom-meta")
	if _, ok := base.Dom["style[data-upstream]"]; !ok {
		t.Fatal("expected upstream DOM rule to remain")
	}
	if _, ok := base.Dom["style[data-custom]"]; !ok {
		t.Fatal("expected custom DOM rule to be added")
	}
	if base.Description != "custom description" {
		t.Fatalf("expected explicit custom metadata to override, got %q", base.Description)
	}
}

func writeCustomFingerprintFile(t *testing.T, contents string) string {
	t.Helper()

	fingerprintPath := filepath.Join(t.TempDir(), "fingerprints.json")
	if err := os.WriteFile(fingerprintPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write custom fingerprints: %v", err)
	}
	return fingerprintPath
}

func assertStringSliceContains(t *testing.T, values []string, expected string) {
	t.Helper()

	for _, value := range values {
		if value == expected {
			return
		}
	}
	t.Fatalf("expected %q in %v", expected, values)
}
