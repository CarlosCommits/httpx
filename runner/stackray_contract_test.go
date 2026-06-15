package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/goflags"
)

func TestStackrayContractTechDetectJSONShape(t *testing.T) {
	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "Stackray Contract App": {
      "cats": [59],
      "html": ["stackray-contract-marker"],
      "headers": {
        "x-stackray-contract": "enabled"
      }
    }
  }
}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Stackray-Contract", "enabled")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><title>Stackray contract</title><body>stackray-contract-marker</body>`))
	}))
	t.Cleanup(server.Close)

	var results []Result
	options := &Options{
		InputTargetHost:       goflags.StringSlice{server.URL},
		Methods:               http.MethodGet,
		TechDetect:            true,
		JSONOutput:            true,
		CustomFingerprintFile: fingerprintPath,
		Threads:               1,
		Retries:               0,
		Timeout:               5,
		DisableStdout:         true,
		DisableUpdateCheck:    true,
		OnResult: func(r Result) {
			results = append(results, r)
		},
	}
	if err := options.ValidateOptions(); err != nil {
		t.Fatalf("expected Stackray contract options to validate: %v", err)
	}

	httpxRunner, err := New(options)
	if err != nil {
		t.Fatalf("expected Stackray contract runner to initialize: %v", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	if len(results) != 1 {
		t.Fatalf("expected one Stackray contract result, got %d", len(results))
	}

	result := results[0]
	if result.Err != nil {
		t.Fatalf("expected successful Stackray contract result: %v", result.Err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, result.StatusCode)
	}
	assertStringSliceContains(t, result.Technologies, "Stackray Contract App")

	var row map[string]any
	if err := json.Unmarshal([]byte(result.JSON(&httpxRunner.scanopts)), &row); err != nil {
		t.Fatalf("expected Stackray JSONL row to be valid JSON: %v", err)
	}
	if _, ok := row["url"].(string); !ok {
		t.Fatalf("expected Stackray JSONL row to contain url string, got %#v", row["url"])
	}
	if got, ok := row["status_code"].(float64); !ok || int(got) != http.StatusOK {
		t.Fatalf("expected Stackray JSONL row to contain status_code %d, got %#v", http.StatusOK, row["status_code"])
	}
	techValues, ok := row["tech"].([]any)
	if !ok {
		t.Fatalf("expected Stackray JSONL row to contain tech array, got %#v", row["tech"])
	}
	if !jsonArrayContainsString(techValues, "Stackray Contract App") {
		t.Fatalf("expected Stackray JSONL tech array to include custom app, got %#v", techValues)
	}
	if _, ok := row["TechnologyDetails"]; ok {
		t.Fatal("expected internal TechnologyDetails to stay out of Stackray JSONL output")
	}
	if _, ok := row["technology_details"]; ok {
		t.Fatal("expected internal technology_details to stay out of Stackray JSONL output")
	}
}

func TestStackrayContractCPEDetectLoadsCustomFingerprints(t *testing.T) {
	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "Stackray CPE Contract App": {
      "cats": [59],
      "html": ["stackray-cpe-contract-marker"]
    }
  }
}`)

	options := &Options{
		CPEDetect:             true,
		CustomFingerprintFile: fingerprintPath,
		DisableUpdateCheck:    true,
	}
	httpxRunner, err := New(options)
	if err != nil {
		t.Fatalf("expected Stackray CPE contract runner to initialize: %v", err)
	}
	defer httpxRunner.Close()

	matches := httpxRunner.wappalyzer.FingerprintWithInfo(nil, []byte("stackray-cpe-contract-marker"))
	if _, ok := matches["Stackray CPE Contract App"]; !ok {
		t.Fatalf("expected -cpe to initialize custom Wappalyzer fingerprints, got %#v", matches)
	}
}

func TestStackrayContractHeadlessTechDetectLoadsCustomFingerprints(t *testing.T) {
	fingerprintPath := writeCustomFingerprintFile(t, `{
  "apps": {
    "Stackray Headless Contract App": {
      "cats": [59],
      "html": ["stackray-headless-contract-marker"]
    }
  }
}`)

	if !wappalyzerRequired(&Options{HeadlessTechDetect: true}) {
		t.Fatal("expected -tdh to require Wappalyzer initialization")
	}

	wappalyzerClient, err := newWappalyzerClient(fingerprintPath)
	if err != nil {
		t.Fatalf("expected Stackray headless custom fingerprints to initialize: %v", err)
	}

	matches := wappalyzerClient.FingerprintWithInfo(nil, []byte("stackray-headless-contract-marker"))
	if _, ok := matches["Stackray Headless Contract App"]; !ok {
		t.Fatalf("expected -tdh to initialize custom Wappalyzer fingerprints, got %#v", matches)
	}
}

func TestStackrayContractHeadlessTitleJSONShape(t *testing.T) {
	result := Result{
		URL:           "https://example.com",
		Title:         "Rendered Browser Title",
		HeadlessTitle: "Rendered Browser Title",
	}

	var row map[string]any
	if err := json.Unmarshal([]byte(result.JSON(nil)), &row); err != nil {
		t.Fatalf("expected Stackray JSONL row to be valid JSON: %v", err)
	}
	if got := row["title"]; got != "Rendered Browser Title" {
		t.Fatalf("expected title to contain rendered browser title, got %#v", got)
	}
	if got := row["headless_title"]; got != "Rendered Browser Title" {
		t.Fatalf("expected headless_title to contain rendered browser title, got %#v", got)
	}
}

func TestStackrayContractVersionedCPEJSONShape(t *testing.T) {
	result := Result{
		URL: "https://example.com",
		CPE: []CPEInfo{
			{
				Product: "WordPress",
				Vendor:  "wordpress",
				CPE:     "cpe:2.3:a:wordpress:wordpress:6.5.0:*:*:*:*:*:*:*",
			},
		},
	}

	var row map[string]any
	if err := json.Unmarshal([]byte(result.JSON(nil)), &row); err != nil {
		t.Fatalf("expected Stackray CPE JSONL row to be valid JSON: %v", err)
	}
	rawCPE, ok := row["cpe"].([]any)
	if !ok || len(rawCPE) != 1 {
		t.Fatalf("expected Stackray JSONL row to contain one CPE object, got %#v", row["cpe"])
	}
	cpeEntry, ok := rawCPE[0].(map[string]any)
	if !ok {
		t.Fatalf("expected CPE entry to be an object, got %#v", rawCPE[0])
	}
	if cpeEntry["cpe"] != "cpe:2.3:a:wordpress:wordpress:6.5.0:*:*:*:*:*:*:*" {
		t.Fatalf("expected versioned CPE string to be preserved, got %#v", cpeEntry["cpe"])
	}
	if cpeEntry["vendor"] != "wordpress" || cpeEntry["product"] != "WordPress" {
		t.Fatalf("expected CPE vendor/product to be preserved, got %#v", cpeEntry)
	}
}

func TestStackrayContractRuntimeTechnologyMetricsJSONShape(t *testing.T) {
	result := Result{
		URL: "https://example.com",
		TechDetectMetrics: &RuntimeTechnologyDetectionMetrics{
			Enabled:                      true,
			Partial:                      true,
			StopReason:                   "artifact_capture_failed",
			DurationMs:                   1234,
			PhaseDurationsMs:             map[string]int64{"script_bodies": 456},
			NetworkRequestCount:          10,
			ScriptBodiesFetched:          3,
			MatchedTechnologyCount:       5,
			PendingSameOriginScriptCount: 1,
		},
	}

	var row map[string]any
	if err := json.Unmarshal([]byte(result.JSON(nil)), &row); err != nil {
		t.Fatalf("expected Stackray JSONL row to be valid JSON: %v", err)
	}
	rawMetrics, ok := row["tech_detection_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected tech_detection_metrics object, got %#v", row["tech_detection_metrics"])
	}
	if rawMetrics["stop_reason"] != "artifact_capture_failed" {
		t.Fatalf("expected stop_reason to be serialized, got %#v", rawMetrics["stop_reason"])
	}
	if rawMetrics["partial"] != true {
		t.Fatalf("expected partial to be serialized, got %#v", rawMetrics["partial"])
	}
	if got, ok := rawMetrics["duration_ms"].(float64); !ok || int(got) != 1234 {
		t.Fatalf("expected duration_ms 1234, got %#v", rawMetrics["duration_ms"])
	}
	phaseDurations, ok := rawMetrics["phase_durations_ms"].(map[string]any)
	if !ok {
		t.Fatalf("expected phase_durations_ms object, got %#v", rawMetrics["phase_durations_ms"])
	}
	if got, ok := phaseDurations["script_bodies"].(float64); !ok || int(got) != 456 {
		t.Fatalf("expected script_bodies phase duration 456, got %#v", phaseDurations["script_bodies"])
	}
}

func TestStackrayContractHeadlessFaviconHash(t *testing.T) {
	faviconBytes, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatalf("expected test favicon fixture to decode: %v", err)
	}

	runner := &Runner{}
	mmh3, md5h, faviconPath, faviconData, faviconURL := runner.HandleHeadlessFaviconHash([]HeadlessFavicon{
		{
			Path: "/not-an-image.txt",
			URL:  "https://example.com/not-an-image.txt",
			Data: []byte("not an image"),
		},
		{
			Path: "/favicon.ico",
			URL:  "https://example.com/favicon.ico",
			Data: faviconBytes,
		},
	})

	if mmh3 == "" {
		t.Fatal("expected headless favicon mmh3 hash to be populated")
	}
	if md5h == "" {
		t.Fatal("expected headless favicon md5 hash to be populated")
	}
	if faviconPath != "/favicon.ico" {
		t.Fatalf("expected favicon path to come from first valid headless favicon, got %q", faviconPath)
	}
	if faviconURL != "https://example.com/favicon.ico" {
		t.Fatalf("expected favicon url to come from first valid headless favicon, got %q", faviconURL)
	}
	if !bytes.Equal(faviconData, faviconBytes) {
		t.Fatal("expected favicon data to come from first valid headless favicon")
	}
}

func TestStackrayContractFaviconCandidatesIgnorePlainAlternateLinks(t *testing.T) {
	html := []byte(`<!doctype html>
<html>
  <head>
    <link rel="alternate" href="https://example.com/fr/" hreflang="fr" />
    <link rel="stylesheet" href="/style.css" />
  </head>
</html>`)

	candidates, _, err := extractPotentialFavIconsURLs(html)
	if err != nil {
		t.Fatalf("expected favicon candidates to parse: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected plain alternate links to be ignored as favicon candidates, got %#v", candidates)
	}

	candidates = appendDefaultFaviconCandidate(candidates)
	if len(candidates) != 1 || candidates[0] != "/favicon.ico" {
		t.Fatalf("expected default favicon fallback candidate, got %#v", candidates)
	}
}

func jsonArrayContainsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
