package runner

import "testing"

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
