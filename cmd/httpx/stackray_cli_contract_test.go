package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStackrayCLIContractTechDetectJSONL(t *testing.T) {
	fingerprintPath := writeStackrayCLIFingerprintFile(t, `{
  "apps": {
    "Stackray CLI Contract App": {
      "cats": [59],
      "html": ["stackray-cli-contract-marker"],
      "headers": {
        "x-stackray-cli-contract": "enabled"
      }
    }
  }
}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Stackray-CLI-Contract", "enabled")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><title>Stackray CLI contract</title><body>stackray-cli-contract-marker</body>`))
	}))
	t.Cleanup(server.Close)

	cmd := exec.Command(
		"go",
		"run",
		".",
		"-silent",
		"-json",
		"-td",
		"-cff",
		fingerprintPath,
		"-u",
		server.URL,
		"-retries",
		"0",
		"-timeout",
		"5",
		"-duc",
	)
	cmd.Dir = "."

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected httpx CLI Stackray contract run to pass: %v\n%s", err, output)
	}

	row := firstJSONLRow(t, output)
	if _, ok := row["url"].(string); !ok {
		t.Fatalf("expected Stackray CLI JSONL row to contain url string, got %#v", row["url"])
	}
	if got, ok := row["status_code"].(float64); !ok || int(got) != http.StatusOK {
		t.Fatalf("expected Stackray CLI JSONL row to contain status_code %d, got %#v", http.StatusOK, row["status_code"])
	}
	techValues, ok := row["tech"].([]any)
	if !ok {
		t.Fatalf("expected Stackray CLI JSONL row to contain tech array, got %#v", row["tech"])
	}
	if !stackrayJSONArrayContainsString(techValues, "Stackray CLI Contract App") {
		t.Fatalf("expected Stackray CLI JSONL tech array to include custom app, got %#v", techValues)
	}
	if _, ok := row["TechnologyDetails"]; ok {
		t.Fatal("expected internal TechnologyDetails to stay out of Stackray CLI JSONL output")
	}
	if _, ok := row["technology_details"]; ok {
		t.Fatal("expected internal technology_details to stay out of Stackray CLI JSONL output")
	}
}

func writeStackrayCLIFingerprintFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stackray-cli-fingerprints.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write Stackray CLI fingerprint file: %v", err)
	}
	return path
}

func firstJSONLRow(t *testing.T, output []byte) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatalf("expected valid JSONL row, got %q: %v", line, err)
		}
		return row
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to scan httpx CLI output: %v", err)
	}
	t.Fatalf("expected at least one JSONL row, got %q", output)
	return nil
}

func stackrayJSONArrayContainsString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
