package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	osutils "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type NetworkRequest struct {
	RequestID    string
	URL          string
	Method       string
	ResourceType string
	StatusCode   int
	ErrorType    string
}

type runtimeDOMValue struct {
	Exists     bool              `json:"exists"`
	Text       string            `json:"text,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type runtimeDOMSpec struct {
	Selector   string   `json:"selector"`
	Attributes []string `json:"attributes,omitempty"`
	Properties []string `json:"properties,omitempty"`
	NeedsText  bool     `json:"needsText,omitempty"`
}

var (
	viteModuleScriptPattern    = regexp.MustCompile(`<script\b[^>]*\btype=["']module["'][^>]*\bsrc=["'][^"']*/assets/[^"']+\.js["']`)
	viteStylesheetPattern      = regexp.MustCompile(`<link\b[^>]*\brel=["']stylesheet["'][^>]*\bhref=["'][^"']*/assets/[^"']+\.css["']`)
	viteAssetScriptPathPattern = regexp.MustCompile(`/assets/[^/?#]+\.js(?:[?#].*)?$`)
	viteAssetStylePathPattern  = regexp.MustCompile(`/assets/[^/?#]+\.css(?:[?#].*)?$`)
)

type HeadlessVisitOptions struct {
	Timeout                 time.Duration
	Idle                    time.Duration
	Headers                 []string
	FullPage                bool
	JSCodes                 []string
	CaptureScreenshot       bool
	DetectRuntimeTechnology bool
	WappalyzerClient        *wappalyzer.Wappalyze
}

type HeadlessVisitResult struct {
	ScreenshotBytes []byte
	Body            string
	NetworkRequests []NetworkRequest
	RuntimeMatches  map[string]wappalyzer.AppInfo
}

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux() && os.Geteuid() == 0
}

type Browser struct {
	tempDir string
	engine  *rod.Browser
	// TODO: Remove the Chrome PID kill code in favor of using Leakless(true).
	// This change will be made if there are no complaints about zombie Chrome processes.
	// Reference: https://github.com/projectdiscovery/httpx/pull/1426
	// pids    map[int32]struct{}
}

func NewBrowser(proxy string, useLocal bool, optionalArgs map[string]string) (*Browser, error) {
	dataStore, err := os.MkdirTemp("", "nuclei-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary directory")
	}

	// pids := processutil.FindProcesses(processutil.IsChromeProcess)

	chromeLauncher := launcher.New().
		Leakless(true).
		Set("disable-gpu", "true").
		Set("ignore-certificate-errors", "true").
		Set("ignore-certificate-errors", "1").
		Set("disable-crash-reporter", "true").
		Set("disable-notifications", "true").
		Set("hide-scrollbars", "true").
		Set("window-size", fmt.Sprintf("%d,%d", 1080, 1920)).
		Set("mute-audio", "true").
		Set("incognito", "true").
		Delete("use-mock-keychain").
		Headless(true).
		UserDataDir(dataStore)

	if MustDisableSandbox() {
		chromeLauncher = chromeLauncher.NoSandbox(true)
	}

	executablePath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	// if musl is used, most likely we are on alpine linux which is not supported by go-rod, so we fallback to default chrome
	useMusl, _ := fileutil.UseMusl(executablePath)
	if useLocal || useMusl {
		if chromePath, hasChrome := launcher.LookPath(); hasChrome {
			chromeLauncher.Bin(chromePath)
		} else {
			return nil, errors.New("the chrome browser is not installed")
		}
	}

	if proxy != "" {
		chromeLauncher = chromeLauncher.Proxy(proxy)
	}

	for k, v := range optionalArgs {
		chromeLauncher.Set(flags.Flag(k), v)
	}

	launcherURL, err := chromeLauncher.Launch()
	if err != nil {
		return nil, err
	}

	browser := rod.New().ControlURL(launcherURL)
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}

	engine := &Browser{
		tempDir: dataStore,
		engine:  browser,
		// pids:    pids,
	}
	return engine, nil
}

func (b *Browser) VisitWithArtifacts(url string, options HeadlessVisitOptions) (*HeadlessVisitResult, error) {
	page, networkRequests, err := b.setupPageAndNavigate(url, options.Timeout, options.Headers, options.JSCodes)
	if err != nil {
		return nil, err
	}
	defer b.closePage(page)

	screenshot, body, err := b.capturePageArtifacts(page, options.Idle, options.FullPage, options.CaptureScreenshot)
	if err != nil {
		return nil, err
	}

	result := &HeadlessVisitResult{
		ScreenshotBytes: screenshot,
		Body:            body,
		NetworkRequests: networkRequests,
		RuntimeMatches:  map[string]wappalyzer.AppInfo{},
	}
	if options.DetectRuntimeTechnology {
		result.RuntimeMatches = b.detectRuntimeTechnologies(page, networkRequests, body, options.WappalyzerClient)
	}

	return result, nil
}

// setupPageAndNavigate opens a page, performs all adaptive actions including JS injection
func (b *Browser) setupPageAndNavigate(url string, timeout time.Duration, headers []string, jsCodes []string) (*rod.Page, []NetworkRequest, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, []NetworkRequest{}, err
	}

	// Enable network
	page.EnableDomain(proto.NetworkEnable{})

	networkRequests := sliceutil.NewSyncSlice[NetworkRequest]()
	requestsMap := mapsutil.NewSyncLockMap[string, *NetworkRequest]()

	// Intercept outbound requests
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if !stringsutil.HasPrefixAnyI(e.Request.URL, "http://", "https://") {
			return
		}
		req := &NetworkRequest{
			RequestID:    string(e.RequestID),
			URL:          e.Request.URL,
			Method:       e.Request.Method,
			ResourceType: string(e.Type),
			StatusCode:   -1,
			ErrorType:    "QUIT_BEFORE_RESOURCE_LOADING_END",
		}
		_ = requestsMap.Set(string(e.RequestID), req)
	})()
	// Intercept inbound responses
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			req.StatusCode = e.Response.Status
			if req.ResourceType == "" {
				req.ResourceType = string(e.Type)
			}
		}
	})()
	// Intercept network end requests
	go page.EachEvent(func(e *proto.NetworkLoadingFinished) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			if req.StatusCode > 0 {
				req.ErrorType = ""
			}
			networkRequests.Append(*req)
		}
	})()
	// Intercept failed request
	go page.EachEvent(func(e *proto.NetworkLoadingFailed) {
		if requestsMap.Has(string(e.RequestID)) {
			req, _ := requestsMap.Get(string(e.RequestID))
			req.StatusCode = 0 // mark to zero
			req.ErrorType = getSimpleErrorType(e.ErrorText, string(e.Type), string(e.BlockedReason))
			if stringsutil.HasPrefixAnyI(req.URL, "http://", "https://") {
				networkRequests.Append(*req)
			}
		}
	})()

	// Handle any popup dialogs
	go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(page)
	})()

	for _, header := range headers {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			continue
		}
		key := strings.TrimSpace(headerParts[0])
		value := strings.TrimSpace(headerParts[1])
		_, _ = page.SetExtraHeaders([]string{key, value})
	}

	page = page.Timeout(timeout)

	if err := page.Navigate(url); err != nil {
		return page, networkRequests.Slice, err
	}

	if len(jsCodes) > 0 {
		_, err := b.ExecuteJavascriptCodesWithPage(page, jsCodes)
		if err != nil {
			return page, networkRequests.Slice, err
		}
	}

	page.Timeout(5 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()

	return page, networkRequests.Slice, nil
}

// capturePageArtifacts waits for the page and returns rendered HTML with optional screenshot bytes.
func (b *Browser) capturePageArtifacts(page *rod.Page, idle time.Duration, fullPage bool, captureScreenshot bool) ([]byte, string, error) {
	if err := page.WaitLoad(); err != nil {
		return nil, "", err
	}
	_ = page.WaitIdle(idle)

	var screenshot []byte
	if captureScreenshot {
		var err error
		screenshot, err = page.Screenshot(fullPage, &proto.PageCaptureScreenshot{})
		if err != nil {
			return nil, "", err
		}
	}

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", err
	}

	return screenshot, body, nil
}

// closePage closes the page and performs cleanup
func (b *Browser) closePage(page *rod.Page) {
	_ = page.Close()
}

func (b *Browser) Close() {
	_ = b.engine.Close()
	_ = os.RemoveAll(b.tempDir)
	// processutil.CloseProcesses(processutil.IsChromeProcess, b.pids)
}
func getSimpleErrorType(errorText, errorType, blockedReason string) string {
	switch blockedReason {
	case "csp":
		return "CSP_BLOCKED"
	case "mixed-content":
		return "MIXED_CONTENT"
	case "origin":
		return "CORS_BLOCKED"
	case "subresource-filter":
		return "AD_BLOCKED"
	}
	switch {
	case strings.Contains(errorText, "net::ERR_NAME_NOT_RESOLVED"):
		return "DNS_ERROR"
	case strings.Contains(errorText, "net::ERR_CONNECTION_REFUSED"):
		return "CONNECTION_REFUSED"
	case strings.Contains(errorText, "net::ERR_CONNECTION_TIMED_OUT"):
		return "TIMEOUT"
	case strings.Contains(errorText, "net::ERR_CERT_"):
		return "SSL_ERROR"
	case strings.Contains(errorText, "net::ERR_BLOCKED_BY_CLIENT"):
		return "CLIENT_BLOCKED"
	case strings.Contains(errorText, "net::ERR_EMPTY_RESPONSE"):
		return "EMPTY_RESPONSE"
	}
	switch errorType {
	case "Failed":
		return "NETWORK_FAILED"
	case "Aborted":
		return "ABORTED"
	case "TimedOut":
		return "TIMEOUT"
	case "AccessDenied":
		return "ACCESS_DENIED"
	case "ConnectionClosed":
		return "CONNECTION_CLOSED"
	case "ConnectionReset":
		return "CONNECTION_RESET"
	case "ConnectionRefused":
		return "CONNECTION_REFUSED"
	case "NameNotResolved":
		return "DNS_ERROR"
	case "BlockedByClient":
		return "CLIENT_BLOCKED"
	}
	// Fallback
	if errorText != "" {
		return "OTHER_ERROR"
	}
	return "UNKNOWN"
}

func (b *Browser) ExecuteJavascriptCodesWithPage(page *rod.Page, jsc []string) ([]*proto.RuntimeRemoteObject, error) {
	outputs := make([]*proto.RuntimeRemoteObject, 0, len(jsc))
	for _, js := range jsc {
		if js == "" {
			continue
		}
		output, err := page.Eval(js)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func (b *Browser) detectRuntimeTechnologies(page *rod.Page, networkRequests []NetworkRequest, pageBody string, wappalyzerClient *wappalyzer.Wappalyze) map[string]wappalyzer.AppInfo {
	technologies := map[string]wappalyzer.AppInfo{}
	if wappalyzerClient == nil {
		return technologies
	}

	originalFingerprints := wappalyzerClient.GetFingerprints()
	if originalFingerprints == nil {
		return technologies
	}

	jsValues := b.collectRuntimeJSValues(page, wappalyzerClient)
	domValues := b.collectRuntimeDOMValues(page, originalFingerprints)
	browserCookies := b.collectRuntimeCookies(page)
	pageOrigin := b.collectRuntimePageOrigin(page)
	scriptBodies := b.collectRuntimeResourceBodies(page, networkRequests, pageOrigin, isLikelyScriptRequest)
	cssBodies := b.collectRuntimeResourceBodies(page, networkRequests, pageOrigin, isLikelyCSSRequest)

	for app, fingerprint := range originalFingerprints.Apps {
		version := ""
		matched := false

		for propertyPath, patternString := range fingerprint.JS {
			value, ok := jsValues[propertyPath]
			if !ok {
				continue
			}

			pattern, err := wappalyzer.ParsePattern(patternString)
			if err != nil {
				continue
			}

			valid, versionString := pattern.Evaluate(value)
			if !valid || pattern.Confidence == 0 {
				continue
			}

			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchDOMFingerprint(fingerprint, domValues); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchCookieFingerprint(fingerprint, browserCookies); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchScriptSrcFingerprint(fingerprint, networkRequests); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchScriptBodyFingerprint(fingerprint, scriptBodies); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchCSSFingerprint(fingerprint, cssBodies); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if !matched {
			continue
		}

		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, app, version)
	}

	addRuntimeBundleTechnologies(technologies, wappalyzerClient, originalFingerprints, pageBody, networkRequests, scriptBodies)

	return technologies
}

func addRuntimeTechnology(technologies map[string]wappalyzer.AppInfo, wappalyzerClient *wappalyzer.Wappalyze, originalFingerprints *wappalyzer.Fingerprints, app string, version string) {
	technologyName := app
	if version != "" {
		technologyName = wappalyzer.FormatAppVersion(app, version)
	}

	if compiledFingerprint, ok := wappalyzerClient.GetCompiledFingerprints().Apps[app]; ok {
		technologies[technologyName] = wappalyzer.AppInfoFromFingerprint(compiledFingerprint)
	}

	if originalFingerprint, ok := originalFingerprints.Apps[app]; ok {
		for _, implied := range originalFingerprint.Implies {
			if impliedFingerprint, ok := wappalyzerClient.GetCompiledFingerprints().Apps[implied]; ok {
				technologies[implied] = wappalyzer.AppInfoFromFingerprint(impliedFingerprint)
			}
		}
	}
}

func addRuntimeBundleTechnologies(technologies map[string]wappalyzer.AppInfo, wappalyzerClient *wappalyzer.Wappalyze, originalFingerprints *wappalyzer.Fingerprints, pageBody string, networkRequests []NetworkRequest, scriptBodies []string) {
	if hasReactBundleEvidence(scriptBodies) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "React", "")
	}
	if hasViteBundleEvidence(pageBody, networkRequests, scriptBodies) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "Vite", "")
	}
}

func (b *Browser) collectRuntimeJSValues(page *rod.Page, wappalyzerClient *wappalyzer.Wappalyze) map[string]string {
	propertyPaths := make([]string, 0)
	seen := map[string]struct{}{}

	for _, fingerprint := range wappalyzerClient.GetCompiledFingerprints().Apps {
		for propertyPath := range fingerprint.GetJSRules() {
			if _, ok := seen[propertyPath]; ok {
				continue
			}
			seen[propertyPath] = struct{}{}
			propertyPaths = append(propertyPaths, propertyPath)
		}
	}

	values := map[string]string{}
	const chunkSize = 250
	for start := 0; start < len(propertyPaths); start += chunkSize {
		end := start + chunkSize
		if end > len(propertyPaths) {
			end = len(propertyPaths)
		}

		chunkValues, err := b.collectRuntimeJSValueChunk(page, propertyPaths[start:end])
		if err != nil {
			continue
		}
		for propertyPath, value := range chunkValues {
			values[propertyPath] = value
		}
	}

	return values
}

func (b *Browser) collectRuntimeJSValueChunk(page *rod.Page, propertyPaths []string) (map[string]string, error) {
	encodedPaths, err := json.Marshal(propertyPaths)
	if err != nil {
		return nil, err
	}

	js := fmt.Sprintf(`() => {
const paths = %s;
const readValue = (path) => {
  const parts = path.split(".");
  let value = window;
  for (const part of parts) {
    if (value == null) return null;
    value = value[part];
  }
  if (value == null || typeof value === "undefined") return null;
  const valueType = typeof value;
  if (valueType === "string" || valueType === "number" || valueType === "boolean") return String(value);
  if (valueType === "function") return "[function]";
  try {
    return String(value);
  } catch (_) {
    return null;
  }
};
const values = {};
for (const path of paths) {
  const value = readValue(path);
  if (value !== null) values[path] = value;
}
return JSON.stringify(values);
}`, string(encodedPaths))

	output, err := page.Eval(js)
	if err != nil {
		return nil, err
	}

	rawValue := fmt.Sprint(output.Value)
	var encodedValue string
	if err := json.Unmarshal([]byte(rawValue), &encodedValue); err != nil {
		encodedValue = rawValue
	}

	values := map[string]string{}
	if err := json.Unmarshal([]byte(encodedValue), &values); err != nil {
		return nil, err
	}

	return values, nil
}

func (b *Browser) collectRuntimeDOMValues(page *rod.Page, fingerprints *wappalyzer.Fingerprints) map[string]runtimeDOMValue {
	specsBySelector := map[string]*runtimeDOMSpec{}

	for _, fingerprint := range fingerprints.Apps {
		for selector, rules := range fingerprint.Dom {
			if selector == "" {
				continue
			}

			spec := specsBySelector[selector]
			if spec == nil {
				spec = &runtimeDOMSpec{Selector: selector}
				specsBySelector[selector] = spec
			}

			for ruleName, ruleValue := range rules {
				switch ruleName {
				case "text":
					spec.NeedsText = true
				case "attributes":
					for name := range toStringInterfaceMap(ruleValue) {
						spec.Attributes = appendUniqueString(spec.Attributes, name)
					}
				case "properties":
					for name := range toStringInterfaceMap(ruleValue) {
						spec.Properties = appendUniqueString(spec.Properties, name)
					}
				}
			}
		}

	}

	specs := make([]runtimeDOMSpec, 0, len(specsBySelector))
	for _, spec := range specsBySelector {
		specs = append(specs, *spec)
	}

	values := map[string]runtimeDOMValue{}
	const chunkSize = 100
	for start := 0; start < len(specs); start += chunkSize {
		end := start + chunkSize
		if end > len(specs) {
			end = len(specs)
		}

		chunkValues, err := b.collectRuntimeDOMValueChunk(page, specs[start:end])
		if err != nil {
			continue
		}
		for selector, value := range chunkValues {
			values[selector] = value
		}
	}

	return values
}

func (b *Browser) collectRuntimeDOMValueChunk(page *rod.Page, specs []runtimeDOMSpec) (map[string]runtimeDOMValue, error) {
	encodedSpecs, err := json.Marshal(specs)
	if err != nil {
		return nil, err
	}

	js := fmt.Sprintf(`() => {
const specs = %s;
const readProperty = (element, path) => {
  const parts = path.split(".");
  let value = element;
  for (const part of parts) {
    if (value == null) return null;
    value = value[part];
  }
  if (value == null || typeof value === "undefined") return null;
  const valueType = typeof value;
  if (valueType === "string" || valueType === "number" || valueType === "boolean") return String(value);
  if (valueType === "function") return "[function]";
  try {
    return String(value);
  } catch (_) {
    return null;
  }
};
const values = {};
for (const spec of specs) {
  let element = null;
  try {
    element = document.querySelector(spec.selector);
  } catch (_) {
    continue;
  }
  if (!element) continue;
  const result = { exists: true };
  if (spec.needsText) result.text = element.textContent || "";
  if (spec.attributes && spec.attributes.length > 0) {
    result.attributes = {};
    for (const attr of spec.attributes) {
      const value = element.getAttribute(attr);
      if (value !== null) result.attributes[attr] = value;
    }
  }
  if (spec.properties && spec.properties.length > 0) {
    result.properties = {};
    for (const prop of spec.properties) {
      const value = readProperty(element, prop);
      if (value !== null) result.properties[prop] = value;
    }
  }
  values[spec.selector] = result;
}
return JSON.stringify(values);
}`, string(encodedSpecs))

	output, err := page.Eval(js)
	if err != nil {
		return nil, err
	}

	rawValue := fmt.Sprint(output.Value)
	var encodedValue string
	if err := json.Unmarshal([]byte(rawValue), &encodedValue); err != nil {
		encodedValue = rawValue
	}

	values := map[string]runtimeDOMValue{}
	if err := json.Unmarshal([]byte(encodedValue), &values); err != nil {
		return nil, err
	}

	return values, nil
}

func (b *Browser) collectRuntimeCookies(page *rod.Page) map[string]string {
	output, err := page.Eval(`() => document.cookie`)
	if err != nil {
		return map[string]string{}
	}

	rawValue := fmt.Sprint(output.Value)
	var cookieString string
	if err := json.Unmarshal([]byte(rawValue), &cookieString); err != nil {
		cookieString = rawValue
	}

	cookies := map[string]string{}
	for _, cookiePart := range strings.Split(cookieString, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(cookiePart), "=")
		if !found || key == "" {
			continue
		}
		cookies[strings.ToLower(key)] = strings.ToLower(value)
	}

	return cookies
}

func (b *Browser) collectRuntimePageOrigin(page *rod.Page) string {
	output, err := page.Eval(`() => window.location.origin`)
	if err != nil {
		return ""
	}

	rawValue := fmt.Sprint(output.Value)
	var origin string
	if err := json.Unmarshal([]byte(rawValue), &origin); err != nil {
		origin = rawValue
	}

	return strings.ToLower(origin)
}

func (b *Browser) collectRuntimeResourceBodies(page *rod.Page, networkRequests []NetworkRequest, pageOrigin string, predicate func(NetworkRequest) bool) []string {
	const (
		maxResources      = 20
		maxResourceBytes  = 2 * 1024 * 1024
		maxTotalBodyBytes = 8 * 1024 * 1024
	)

	bodies := make([]string, 0)
	seen := map[string]struct{}{}
	totalBytes := 0

	for _, request := range networkRequests {
		if len(bodies) >= maxResources || totalBytes >= maxTotalBodyBytes {
			break
		}
		if request.RequestID == "" || request.StatusCode != 200 || !predicate(request) {
			continue
		}
		if pageOrigin != "" && !isSameOriginRequest(request.URL, pageOrigin) {
			continue
		}
		if _, ok := seen[request.URL]; ok {
			continue
		}
		seen[request.URL] = struct{}{}

		responseBody, err := proto.NetworkGetResponseBody{
			RequestID: proto.NetworkRequestID(request.RequestID),
		}.Call(page)
		if err != nil {
			continue
		}

		body := responseBody.Body
		if responseBody.Base64Encoded {
			decoded, err := base64.StdEncoding.DecodeString(responseBody.Body)
			if err != nil {
				continue
			}
			body = string(decoded)
		}

		if len(body) == 0 || len(body) > maxResourceBytes {
			continue
		}
		if totalBytes+len(body) > maxTotalBodyBytes {
			continue
		}

		bodies = append(bodies, strings.ToLower(body))
		totalBytes += len(body)
	}

	return bodies
}

func isSameOriginRequest(rawRequestURL string, pageOrigin string) bool {
	requestURL, err := url.Parse(rawRequestURL)
	if err != nil || requestURL.Scheme == "" || requestURL.Host == "" {
		return false
	}

	requestOrigin := strings.ToLower(requestURL.Scheme + "://" + requestURL.Host)
	return requestOrigin == pageOrigin
}

func isLikelyScriptRequest(request NetworkRequest) bool {
	resourceType := strings.ToLower(request.ResourceType)
	url := strings.ToLower(request.URL)

	return resourceType == "script" ||
		strings.Contains(url, ".js") ||
		strings.Contains(url, ".mjs")
}

func isLikelyCSSRequest(request NetworkRequest) bool {
	resourceType := strings.ToLower(request.ResourceType)
	url := strings.ToLower(request.URL)

	return resourceType == "stylesheet" ||
		strings.Contains(url, ".css")
}

func hasReactBundleEvidence(scriptBodies []string) bool {
	for _, body := range scriptBodies {
		if !strings.Contains(body, "@license react") {
			continue
		}
		if strings.Contains(body, "react.production.min.js") ||
			strings.Contains(body, "react-dom.production.min.js") ||
			strings.Contains(body, "react-jsx-runtime.production.min.js") {
			return true
		}
	}

	return false
}

func hasViteBundleEvidence(pageBody string, networkRequests []NetworkRequest, scriptBodies []string) bool {
	body := strings.ToLower(pageBody)
	if strings.Contains(body, "data-vite") {
		return true
	}

	hasModuleAsset := hasViteModuleAsset(body, networkRequests)
	if !hasModuleAsset {
		return false
	}

	return hasViteStylesheetAsset(body, networkRequests) && hasViteModulePreloadEvidence(body, scriptBodies)
}

func hasViteModuleAsset(body string, networkRequests []NetworkRequest) bool {
	if viteModuleScriptPattern.MatchString(body) {
		return true
	}

	for _, request := range networkRequests {
		if strings.EqualFold(request.ResourceType, "script") && viteAssetScriptPathPattern.MatchString(strings.ToLower(request.URL)) {
			return true
		}
	}

	return false
}

func hasViteStylesheetAsset(body string, networkRequests []NetworkRequest) bool {
	if viteStylesheetPattern.MatchString(body) {
		return true
	}

	for _, request := range networkRequests {
		if strings.EqualFold(request.ResourceType, "stylesheet") && viteAssetStylePathPattern.MatchString(strings.ToLower(request.URL)) {
			return true
		}
	}

	return false
}

func hasViteModulePreloadEvidence(body string, scriptBodies []string) bool {
	if strings.Contains(body, "modulepreload") {
		return true
	}

	for _, scriptBody := range scriptBodies {
		if strings.Contains(scriptBody, "modulepreload") {
			return true
		}
	}

	return false
}

func (b *Browser) matchDOMFingerprint(fingerprint *wappalyzer.Fingerprint, domValues map[string]runtimeDOMValue) (bool, string) {
	version := ""

	for selector, rules := range fingerprint.Dom {
		value, ok := domValues[selector]
		if !ok || !value.Exists {
			continue
		}

		for ruleName, ruleValue := range rules {
			switch ruleName {
			case "exists":
				if ok, versionString := evaluateRuntimePattern(fmt.Sprint(ruleValue), "true"); ok {
					version = moreSpecificVersion(version, versionString)
					return true, version
				}
			case "text":
				if ok, versionString := evaluateRuntimePattern(fmt.Sprint(ruleValue), value.Text); ok {
					version = moreSpecificVersion(version, versionString)
					return true, version
				}
			case "attributes":
				for name, pattern := range toStringInterfaceMap(ruleValue) {
					attributeValue, found := value.Attributes[name]
					if !found {
						continue
					}
					if ok, versionString := evaluateRuntimePattern(fmt.Sprint(pattern), attributeValue); ok {
						version = moreSpecificVersion(version, versionString)
						return true, version
					}
				}
			case "properties":
				for name, pattern := range toStringInterfaceMap(ruleValue) {
					propertyValue, found := value.Properties[name]
					if !found {
						continue
					}
					if ok, versionString := evaluateRuntimePattern(fmt.Sprint(pattern), propertyValue); ok {
						version = moreSpecificVersion(version, versionString)
						return true, version
					}
				}
			}
		}
	}

	return false, ""
}

func (b *Browser) matchCookieFingerprint(fingerprint *wappalyzer.Fingerprint, cookies map[string]string) (bool, string) {
	version := ""

	for cookieName, patternString := range fingerprint.Cookies {
		value, ok := cookies[strings.ToLower(cookieName)]
		if !ok {
			continue
		}

		if ok, versionString := evaluateRuntimePattern(patternString, value); ok {
			version = moreSpecificVersion(version, versionString)
			return true, version
		}
	}

	return false, ""
}

func (b *Browser) matchScriptSrcFingerprint(fingerprint *wappalyzer.Fingerprint, networkRequests []NetworkRequest) (bool, string) {
	if len(fingerprint.ScriptSrc) == 0 {
		return false, ""
	}

	version := ""

	for _, request := range networkRequests {
		for _, patternString := range fingerprint.ScriptSrc {
			if ok, versionString := evaluateRuntimePattern(patternString, strings.ToLower(request.URL)); ok {
				version = moreSpecificVersion(version, versionString)
				return true, version
			}
		}
	}

	return false, ""
}

func (b *Browser) matchScriptBodyFingerprint(fingerprint *wappalyzer.Fingerprint, scriptBodies []string) (bool, string) {
	if len(fingerprint.Script) == 0 || len(scriptBodies) == 0 {
		return false, ""
	}

	version := ""

	for _, body := range scriptBodies {
		for _, patternString := range fingerprint.Script {
			if ok, versionString := evaluateRuntimePattern(patternString, body); ok {
				version = moreSpecificVersion(version, versionString)
				return true, version
			}
		}
	}

	return false, ""
}

func (b *Browser) matchCSSFingerprint(fingerprint *wappalyzer.Fingerprint, cssBodies []string) (bool, string) {
	if len(fingerprint.CSS) == 0 || len(cssBodies) == 0 {
		return false, ""
	}

	version := ""

	for _, body := range cssBodies {
		for _, patternString := range fingerprint.CSS {
			if ok, versionString := evaluateRuntimePattern(patternString, body); ok {
				version = moreSpecificVersion(version, versionString)
				return true, version
			}
		}
	}

	return false, ""
}

func evaluateRuntimePattern(patternString string, value string) (bool, string) {
	pattern, err := wappalyzer.ParsePattern(patternString)
	if err != nil {
		return false, ""
	}

	valid, versionString := pattern.Evaluate(value)
	return valid && pattern.Confidence > 0, versionString
}

func moreSpecificVersion(current string, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" || len(candidate) > len(current) {
		return candidate
	}
	return current
}

func toStringInterfaceMap(value interface{}) map[string]interface{} {
	typed, ok := value.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}

	return typed
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}
