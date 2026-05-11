package runner

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func newWappalyzerClient(customFingerprintFile string) (*wappalyzer.Wappalyze, error) {
	if customFingerprintFile == "" {
		return wappalyzer.New()
	}

	embeddedClient, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	mergedFingerprints := embeddedClient.GetFingerprints()
	if mergedFingerprints == nil {
		return nil, errors.New("embedded wappalyzer fingerprints are unavailable")
	}

	customContents, err := os.ReadFile(customFingerprintFile)
	if err != nil {
		return nil, err
	}

	var customFingerprints wappalyzer.Fingerprints
	if err := json.Unmarshal(customContents, &customFingerprints); err != nil {
		return nil, err
	}
	if len(customFingerprints.Apps) == 0 {
		return nil, errors.Errorf("no fingerprints found in file: %s", customFingerprintFile)
	}

	mergeFingerprints(mergedFingerprints, &customFingerprints)

	mergedContents, err := json.Marshal(mergedFingerprints)
	if err != nil {
		return nil, err
	}

	mergedFile, err := os.CreateTemp("", "httpx-wappalyzer-fingerprints-*.json")
	if err != nil {
		return nil, err
	}
	mergedPath := mergedFile.Name()
	defer os.Remove(mergedPath)

	if _, err := mergedFile.Write(mergedContents); err != nil {
		mergedFile.Close()
		return nil, err
	}
	if err := mergedFile.Close(); err != nil {
		return nil, err
	}

	return wappalyzer.NewFromFile(mergedPath, false, false)
}

func mergeFingerprints(base, custom *wappalyzer.Fingerprints) {
	if base.Apps == nil {
		base.Apps = map[string]*wappalyzer.Fingerprint{}
	}

	for app, customFingerprint := range custom.Apps {
		baseFingerprint, ok := base.Apps[app]
		if !ok {
			base.Apps[app] = customFingerprint
			continue
		}

		mergeFingerprint(baseFingerprint, customFingerprint)
	}
}

func mergeFingerprint(base, custom *wappalyzer.Fingerprint) {
	base.Cats = appendUniqueInts(base.Cats, custom.Cats)
	base.CSS = appendUniqueStrings(base.CSS, custom.CSS)
	base.HTML = appendUniqueStrings(base.HTML, custom.HTML)
	base.Script = appendUniqueStrings(base.Script, custom.Script)
	base.ScriptSrc = appendUniqueStrings(base.ScriptSrc, custom.ScriptSrc)
	base.Implies = appendUniqueStrings(base.Implies, custom.Implies)

	mergeStringMap(&base.Cookies, custom.Cookies)
	mergeStringMap(&base.JS, custom.JS)
	mergeStringMap(&base.Headers, custom.Headers)
	mergeStringSliceMap(&base.Meta, custom.Meta)
	mergeDOMMap(&base.Dom, custom.Dom)

	if custom.Description != "" {
		base.Description = custom.Description
	}
	if custom.Website != "" {
		base.Website = custom.Website
	}
	if custom.Icon != "" {
		base.Icon = custom.Icon
	}
	if custom.CPE != "" {
		base.CPE = custom.CPE
	}
}

func appendUniqueStrings(base []string, custom []string) []string {
	seen := make(map[string]struct{}, len(base)+len(custom))
	for _, value := range base {
		seen[value] = struct{}{}
	}
	for _, value := range custom {
		if _, ok := seen[value]; ok {
			continue
		}
		base = append(base, value)
		seen[value] = struct{}{}
	}
	return base
}

func appendUniqueInts(base []int, custom []int) []int {
	seen := make(map[int]struct{}, len(base)+len(custom))
	for _, value := range base {
		seen[value] = struct{}{}
	}
	for _, value := range custom {
		if _, ok := seen[value]; ok {
			continue
		}
		base = append(base, value)
		seen[value] = struct{}{}
	}
	return base
}

func mergeStringMap(base *map[string]string, custom map[string]string) {
	if len(custom) == 0 {
		return
	}
	if *base == nil {
		*base = map[string]string{}
	}
	for key, value := range custom {
		(*base)[key] = value
	}
}

func mergeStringSliceMap(base *map[string][]string, custom map[string][]string) {
	if len(custom) == 0 {
		return
	}
	if *base == nil {
		*base = map[string][]string{}
	}
	for key, values := range custom {
		(*base)[key] = appendUniqueStrings((*base)[key], values)
	}
}

func mergeDOMMap(base *map[string]map[string]interface{}, custom map[string]map[string]interface{}) {
	if len(custom) == 0 {
		return
	}
	if *base == nil {
		*base = map[string]map[string]interface{}{}
	}
	for selector, customRules := range custom {
		baseRules := (*base)[selector]
		if baseRules == nil {
			(*base)[selector] = customRules
			continue
		}
		for key, value := range customRules {
			baseRules[key] = value
		}
	}
}
