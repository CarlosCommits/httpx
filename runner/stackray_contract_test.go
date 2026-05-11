package runner

import (
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

func jsonArrayContainsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
