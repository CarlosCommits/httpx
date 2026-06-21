package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	osutils "github.com/projectdiscovery/utils/os"
	stringsutil "github.com/projectdiscovery/utils/strings"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type NetworkRequest struct {
	RequestID       string
	URL             string
	Method          string
	ResourceType    string
	StatusCode      int
	ErrorType       string
	ResponseHeaders map[string]string `json:"-"`
}

type headlessNetworkTracker struct {
	mu        sync.Mutex
	requests  map[string]*NetworkRequest
	order     []string
	lastEvent time.Time
}

func newHeadlessNetworkTracker() *headlessNetworkTracker {
	return &headlessNetworkTracker{
		requests:  make(map[string]*NetworkRequest),
		lastEvent: time.Now(),
	}
}

func (t *headlessNetworkTracker) start(request NetworkRequest) {
	if request.RequestID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.requests[request.RequestID]; !ok {
		t.order = append(t.order, request.RequestID)
	}
	requestCopy := request
	t.requests[request.RequestID] = &requestCopy
	t.lastEvent = time.Now()
}

func (t *headlessNetworkTracker) response(requestID string, status int, resourceType string, headers proto.NetworkHeaders) {
	t.mu.Lock()
	defer t.mu.Unlock()

	request, ok := t.requests[requestID]
	if !ok {
		return
	}
	request.StatusCode = status
	if request.ResourceType == "" {
		request.ResourceType = resourceType
	}
	request.ResponseHeaders = normalizeNetworkHeaders(headers)
	t.lastEvent = time.Now()
}

func (t *headlessNetworkTracker) finish(requestID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	request, ok := t.requests[requestID]
	if !ok {
		return
	}
	if request.StatusCode > 0 {
		request.ErrorType = ""
	}
	t.lastEvent = time.Now()
}

func (t *headlessNetworkTracker) fail(requestID string, errorType string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	request, ok := t.requests[requestID]
	if !ok {
		return
	}
	request.StatusCode = 0
	request.ErrorType = errorType
	t.lastEvent = time.Now()
}

func (t *headlessNetworkTracker) snapshot() []NetworkRequest {
	t.mu.Lock()
	defer t.mu.Unlock()

	requests := make([]NetworkRequest, 0, len(t.order))
	for _, requestID := range t.order {
		request, ok := t.requests[requestID]
		if !ok {
			continue
		}
		requests = append(requests, *request)
	}

	return requests
}

func (t *headlessNetworkTracker) quietFor(duration time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return time.Since(t.lastEvent) >= duration
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
	scriptSrcPattern           = regexp.MustCompile(`<script\b[^>]*\bsrc=["']([^"']+)["']`)
	modulePreloadHrefPattern   = regexp.MustCompile(`<link\b[^>]*\brel=["']modulepreload["'][^>]*\bhref=["']([^"']+)["']`)
	dynamicImportPattern       = regexp.MustCompile(`import\(["']([^"']+\.m?js(?:\?[^"']*)?)["']\)`)
)

const (
	headlessReadinessTimeout       = 20 * time.Second
	headlessReadinessPollInterval  = 250 * time.Millisecond
	headlessReadinessQuietDuration = 750 * time.Millisecond
	defaultHeadlessAcceptLanguage  = "en-US,en;q=0.9"
	fallbackDesktopChromeUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6568.0 Safari/537.36"
)

type HeadlessVisitOptions struct {
	Timeout                 time.Duration
	Idle                    time.Duration
	Headers                 []string
	FullPage                bool
	JSCodes                 []string
	CaptureScreenshot       bool
	CaptureFavicon          bool
	DetectRuntimeTechnology bool
	WappalyzerClient        *wappalyzer.Wappalyze
}

type HeadlessFavicon struct {
	Path string
	URL  string
	Data []byte
}

type HeadlessVisitResult struct {
	ScreenshotBytes []byte
	Body            string
	Title           string
	Favicons        []HeadlessFavicon
	NetworkRequests []NetworkRequest
	RuntimeMatches  map[string]wappalyzer.AppInfo
	RuntimeMetrics  *RuntimeTechnologyDetectionMetrics
}

type RealChromeRecoveryOptions struct {
	Timeout                 time.Duration
	ArtifactTimeout         time.Duration
	Idle                    time.Duration
	Headers                 []string
	FullPage                bool
	JSCodes                 []string
	CaptureScreenshot       bool
	CaptureFavicon          bool
	DetectRuntimeTechnology bool
	WappalyzerClient        *wappalyzer.Wappalyze
	ChromeBin               string
	Proxy                   string
	SettleTimeout           time.Duration
	WindowSize              string
	ResponseHeaders         map[string][]string
}

type runtimeBodyCollection struct {
	Bodies       []string
	CapturedURLs map[string]struct{}
	Bytes        int
}

type runtimeScriptBodyCollection struct {
	Bodies         []string
	CandidateCount int
	CapturedCount  int
	FetchedCount   int
	Bytes          int
}

type cachedRuntimePattern struct {
	pattern *wappalyzer.ParsedPattern
	ok      bool
}

var runtimePatternCache sync.Map

type headlessFaviconCandidate struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

type headlessFaviconPayload struct {
	Path       string `json:"path"`
	URL        string `json:"url"`
	DataBase64 string `json:"dataBase64"`
}

// MustDisableSandbox determines if the current os and user needs sandbox mode disabled
func MustDisableSandbox() bool {
	// linux with root user needs "--no-sandbox" option
	// https://github.com/chromium/chromium/blob/c4d3c31083a2e1481253ff2d24298a1dfe19c754/chrome/test/chromedriver/client/chromedriver.py#L209
	return osutils.IsLinux() && os.Geteuid() == 0
}

type Browser struct {
	tempDir          string
	engine           *rod.Browser
	defaultUserAgent string
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
		Set("disable-blink-features", "AutomationControlled").
		Set("blink-settings", "primaryPointerType=4,availablePointerTypes=4,primaryHoverType=2,availableHoverTypes=2").
		Set("ozone-override-screen-size", "1365,768").
		Set("window-size", fmt.Sprintf("%d,%d", 1365, 768)).
		Set("mute-audio", "true").
		Delete("enable-automation").
		Delete("use-mock-keychain").
		HeadlessNew(true).
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

	if proxy == "" {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(k); v != "" {
				proxy = v
				break
			}
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

	browser := rod.New().ControlURL(launcherURL).NoDefaultDevice()
	if browserErr := browser.Connect(); browserErr != nil {
		return nil, browserErr
	}

	defaultUserAgent := fallbackDesktopChromeUserAgent
	if version, versionErr := browser.Version(); versionErr == nil {
		if normalizedUserAgent := normalizeHeadlessUserAgent(version.UserAgent); normalizedUserAgent != "" {
			defaultUserAgent = normalizedUserAgent
		}
	}

	engine := &Browser{
		tempDir:          dataStore,
		engine:           browser,
		defaultUserAgent: defaultUserAgent,
		// pids:    pids,
	}
	return engine, nil
}

func (b *Browser) VisitWithArtifacts(url string, options HeadlessVisitOptions) (*HeadlessVisitResult, error) {
	page, networkTracker, err := b.setupPageAndNavigate(url, options.Timeout, options.Headers, options.JSCodes)
	if err != nil {
		return nil, err
	}
	defer b.closePage(page)

	screenshot, body, title, networkRequests, err := b.capturePageArtifacts(page, networkTracker, options.Idle, options.FullPage, options.CaptureScreenshot, options.DetectRuntimeTechnology)
	if err != nil && !options.DetectRuntimeTechnology {
		return nil, err
	}
	if err != nil {
		networkRequests = networkTracker.snapshot()
		if title == "" {
			title = b.captureDocumentTitle(page)
		}
	}

	result := &HeadlessVisitResult{
		ScreenshotBytes: screenshot,
		Body:            body,
		Title:           title,
		NetworkRequests: networkRequests,
		RuntimeMatches:  map[string]wappalyzer.AppInfo{},
	}
	if options.CaptureFavicon {
		result.Favicons = b.collectHeadlessFavicons(page, body, networkRequests)
	}
	if options.DetectRuntimeTechnology {
		result.RuntimeMatches, result.RuntimeMetrics = b.detectRuntimeTechnologies(page, networkRequests, body, options.WappalyzerClient)
		if err != nil && result.RuntimeMetrics != nil {
			result.RuntimeMetrics.Partial = true
			if result.RuntimeMetrics.StopReason == "" || result.RuntimeMetrics.StopReason == "completed" {
				result.RuntimeMetrics.StopReason = "artifact_capture_failed"
			}
		}
	}

	return result, err
}

func VisitWithRealChromeRecovery(targetURL string, options RealChromeRecoveryOptions) (*HeadlessVisitResult, error) {
	if options.SettleTimeout <= 0 {
		options.SettleTimeout = 45 * time.Second
	}
	if options.Idle <= 0 {
		options.Idle = time.Second
	}
	if strings.TrimSpace(options.WindowSize) == "" {
		options.WindowSize = "1365,768"
	}
	if options.ArtifactTimeout <= 0 {
		options.ArtifactTimeout = 10 * time.Second
	}
	if options.Timeout <= 0 {
		options.Timeout = options.SettleTimeout + options.ArtifactTimeout + 10*time.Second
	}

	chromeBin, err := resolveRealChromeBinary(options.ChromeBin)
	if err != nil {
		return nil, err
	}
	dataStore, err := os.MkdirTemp("", "httpx-real-chrome-*")
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary Chrome profile")
	}
	defer os.RemoveAll(dataStore)

	port, err := reserveLocalPort()
	if err != nil {
		return nil, err
	}
	proxy := resolveChromeProxy(options.Proxy)

	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	remainingTimeout := func() time.Duration {
		deadline, ok := ctx.Deadline()
		if !ok {
			return options.Timeout
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Nanosecond
		}
		return remaining
	}
	waitTimeout := func(max time.Duration) time.Duration {
		remaining := remainingTimeout()
		if max <= 0 || remaining < max {
			return remaining
		}
		return max
	}

	controlledNavigation := len(options.Headers) > 0 || len(options.JSCodes) > 0
	launchURL := targetURL
	if controlledNavigation {
		launchURL = "about:blank"
	}
	args := []string{
		"--remote-debugging-address=127.0.0.1",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=" + dataStore,
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--window-size=" + options.WindowSize,
	}
	if MustDisableSandbox() {
		args = append(args, "--no-sandbox")
	}
	if proxy != "" {
		args = append(args, "--proxy-server="+proxy)
	}
	args = append(args, launchURL)

	cmd := exec.CommandContext(ctx, chromeBin, args...)
	if err := cmd.Start(); err != nil {
		return nil, errors.Wrap(err, "could not launch Chrome")
	}
	defer func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	controlURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	websocketURL, err := waitForChromeDebugging(controlURL, waitTimeout(10*time.Second))
	if err != nil {
		return nil, err
	}
	if !controlledNavigation {
		select {
		case <-time.After(waitTimeout(options.SettleTimeout)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	browser := rod.New().ControlURL(websocketURL).NoDefaultDevice()
	if err := browser.Connect(); err != nil {
		return nil, err
	}
	defer browser.Close()

	page, err := selectRealChromeRecoveryPage(browser, launchURL, waitTimeout(options.SettleTimeout))
	if err != nil {
		return nil, err
	}
	defer func() { _ = page.Close() }()

	b := &Browser{
		tempDir:          dataStore,
		engine:           browser,
		defaultUserAgent: fallbackDesktopChromeUserAgent,
	}
	if version, versionErr := browser.Version(); versionErr == nil {
		if normalizedUserAgent := normalizeHeadlessUserAgent(version.UserAgent); normalizedUserAgent != "" {
			b.defaultUserAgent = normalizedUserAgent
		}
	}

	networkTracker := newHeadlessNetworkTracker()
	if controlledNavigation {
		if err := b.navigateExistingPageWithArtifacts(page, targetURL, waitTimeout(options.SettleTimeout), options.Headers, options.JSCodes, networkTracker); err != nil {
			return nil, err
		}
	} else {
		seedRealChromeDocumentRequest(networkTracker, page, normalizeHTTPResponseHeaders(options.ResponseHeaders))
		seedPerformanceResourceRequests(networkTracker, page)
	}
	page = page.Timeout(waitTimeout(options.ArtifactTimeout))
	screenshot, body, title, networkRequests, artifactErr := b.capturePageArtifacts(
		page,
		networkTracker,
		options.Idle,
		options.FullPage,
		options.CaptureScreenshot,
		options.DetectRuntimeTechnology,
	)
	if artifactErr != nil && !options.DetectRuntimeTechnology {
		return nil, artifactErr
	}
	if artifactErr != nil {
		networkRequests = networkTracker.snapshot()
		if title == "" {
			title = b.captureDocumentTitle(page)
		}
	}

	result := &HeadlessVisitResult{
		ScreenshotBytes: screenshot,
		Body:            body,
		Title:           title,
		NetworkRequests: networkRequests,
		RuntimeMatches:  map[string]wappalyzer.AppInfo{},
	}
	if options.CaptureFavicon {
		result.Favicons = b.collectHeadlessFavicons(page, body, networkRequests)
	}
	if options.DetectRuntimeTechnology {
		result.RuntimeMatches, result.RuntimeMetrics = b.detectRuntimeTechnologies(page, networkRequests, body, options.WappalyzerClient)
		if artifactErr != nil && result.RuntimeMetrics != nil {
			result.RuntimeMetrics.Partial = true
			if result.RuntimeMetrics.StopReason == "" || result.RuntimeMetrics.StopReason == "completed" {
				result.RuntimeMetrics.StopReason = "artifact_capture_failed"
			}
		}
	}

	return result, artifactErr
}

func resolveRealChromeBinary(chromeBin string) (string, error) {
	chromeBin = strings.TrimSpace(chromeBin)
	if chromeBin != "" {
		if filepath.IsAbs(chromeBin) {
			return chromeBin, nil
		}
		if resolved, err := exec.LookPath(chromeBin); err == nil {
			return resolved, nil
		}
		return "", fmt.Errorf("Chrome binary not found: %s", chromeBin)
	}
	for _, candidate := range []string{"google-chrome", "google-chrome-stable", "chrome", "chromium", "chromium-browser"} {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	if chromePath, hasChrome := launcher.LookPath(); hasChrome {
		return chromePath, nil
	}
	return "", errors.New("the chrome browser is not installed")
}

func resolveChromeProxy(proxy string) string {
	proxy = strings.TrimSpace(proxy)
	if proxy != "" {
		return proxy
	}
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func reserveLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("could not reserve a TCP port")
	}
	return addr.Port, nil
}

func waitForChromeDebugging(controlURL string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	versionURL := strings.TrimRight(controlURL, "/") + "/json/version"

	for time.Now().Before(deadline) {
		response, err := client.Get(versionURL)
		if err == nil {
			var payload struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&payload)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && payload.WebSocketDebuggerURL != "" {
				return payload.WebSocketDebuggerURL, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}

	return "", fmt.Errorf("Chrome debugging endpoint did not become ready before timeout: %s", controlURL)
}

func selectRealChromeRecoveryPage(browser *rod.Browser, targetURL string, timeout time.Duration) (*rod.Page, error) {
	deadline := time.Now().Add(timeout)
	targetHost := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		targetHost = parsed.Hostname()
	}

	for time.Now().Before(deadline) {
		pages, err := browser.Pages()
		if err == nil {
			var fallback *rod.Page
			for _, page := range pages {
				info, infoErr := page.Info()
				if infoErr != nil || info == nil {
					continue
				}
				pageURL := strings.TrimSpace(info.URL)
				if pageURL == "" || strings.HasPrefix(pageURL, "devtools://") || strings.HasPrefix(pageURL, "chrome://") {
					continue
				}
				if fallback == nil {
					fallback = page
				}
				if targetHost != "" {
					if parsed, parseErr := url.Parse(pageURL); parseErr == nil && sameOrSubdomain(parsed.Hostname(), targetHost) {
						return page, nil
					}
				}
			}
			if fallback != nil {
				return fallback, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return nil, errors.New("could not find a Chrome page target for browser recovery")
}

func seedRealChromeDocumentRequest(networkTracker *headlessNetworkTracker, page *rod.Page, responseHeaders map[string]string) {
	info, err := page.Info()
	if err != nil || info == nil {
		return
	}
	pageURL := strings.TrimSpace(info.URL)
	if pageURL == "" || !stringsutil.HasPrefixAnyI(pageURL, "http://", "https://") {
		return
	}
	networkTracker.start(NetworkRequest{
		RequestID:       "real-chrome-document",
		URL:             pageURL,
		Method:          http.MethodGet,
		ResourceType:    "Document",
		StatusCode:      http.StatusOK,
		ResponseHeaders: responseHeaders,
	})
	networkTracker.finish("real-chrome-document")
}

func normalizeHTTPResponseHeaders(headers map[string][]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(headers))
	for name, values := range headers {
		headerName := strings.ToLower(strings.TrimSpace(name))
		if headerName == "" || len(values) == 0 {
			continue
		}
		normalized[headerName] = strings.ToLower(strings.TrimSpace(strings.Join(values, ",")))
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func seedPerformanceResourceRequests(networkTracker *headlessNetworkTracker, page *rod.Page) {
	output, err := page.Eval(`() => JSON.stringify(performance.getEntriesByType("resource").map((entry) => ({
		name: entry.name || "",
		initiatorType: entry.initiatorType || ""
	})).filter((entry) => /^https?:\/\//i.test(entry.name)).slice(0, 250))`)
	if err != nil {
		return
	}

	rawValue := fmt.Sprint(output.Value)
	var serialized string
	if err := json.Unmarshal([]byte(rawValue), &serialized); err != nil {
		return
	}

	var entries []struct {
		Name          string `json:"name"`
		InitiatorType string `json:"initiatorType"`
	}
	if err := json.Unmarshal([]byte(serialized), &entries); err != nil {
		return
	}

	for index, entry := range entries {
		rawURL := strings.TrimSpace(entry.Name)
		if rawURL == "" {
			continue
		}
		requestID := fmt.Sprintf("performance-resource-%d", index)
		networkTracker.start(NetworkRequest{
			RequestID:    requestID,
			URL:          rawURL,
			Method:       http.MethodGet,
			ResourceType: performanceInitiatorResourceType(entry.InitiatorType),
			StatusCode:   http.StatusOK,
			ErrorType:    "",
		})
		networkTracker.finish(requestID)
	}
}

func performanceInitiatorResourceType(initiatorType string) string {
	switch strings.ToLower(strings.TrimSpace(initiatorType)) {
	case "script":
		return "Script"
	case "css", "link":
		return "Stylesheet"
	case "img", "image":
		return "Image"
	case "xmlhttprequest", "fetch":
		return "XHR"
	case "iframe", "frame":
		return "Document"
	default:
		if strings.TrimSpace(initiatorType) != "" {
			return strings.TrimSpace(initiatorType)
		}
		return "Other"
	}
}

func sameOrSubdomain(hostname, parent string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))
	return hostname == parent || strings.HasSuffix(hostname, "."+parent)
}

func attachNetworkTracker(page *rod.Page, networkTracker *headlessNetworkTracker) error {
	page.EnableDomain(proto.NetworkEnable{})
	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if !stringsutil.HasPrefixAnyI(e.Request.URL, "http://", "https://") {
			return
		}
		networkTracker.start(NetworkRequest{
			RequestID:    string(e.RequestID),
			URL:          e.Request.URL,
			Method:       e.Request.Method,
			ResourceType: string(e.Type),
			StatusCode:   -1,
			ErrorType:    "QUIT_BEFORE_RESOURCE_LOADING_END",
		})
	})()
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		networkTracker.response(string(e.RequestID), e.Response.Status, string(e.Type), e.Response.Headers)
	})()
	go page.EachEvent(func(e *proto.NetworkLoadingFinished) {
		networkTracker.finish(string(e.RequestID))
	})()
	go page.EachEvent(func(e *proto.NetworkLoadingFailed) {
		networkTracker.fail(string(e.RequestID), getSimpleErrorType(e.ErrorText, string(e.Type), string(e.BlockedReason)))
	})()
	return nil
}

func attachDialogAutoAccept(page *rod.Page) {
	go page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		_ = proto.PageHandleJavaScriptDialog{
			Accept:     true,
			PromptText: "",
		}.Call(page)
	})()
}

func (b *Browser) navigateExistingPageWithArtifacts(page *rod.Page, url string, timeout time.Duration, headers []string, jsCodes []string, networkTracker *headlessNetworkTracker) error {
	if err := attachNetworkTracker(page, networkTracker); err != nil {
		return err
	}
	attachDialogAutoAccept(page)

	headerOverrides := parseHeadlessBrowserHeaders(headers)
	if err := b.applyHeadlessBrowserOverrides(page, headerOverrides); err != nil {
		return err
	}
	if _, err := page.EvalOnNewDocument(buildHeadlessStealthScript(headerOverrides.AcceptLanguage)); err != nil {
		return err
	}

	page = page.Timeout(timeout)

	if err := page.Navigate(url); err != nil {
		return err
	}

	if len(jsCodes) > 0 {
		_, err := b.ExecuteJavascriptCodesWithPage(page, jsCodes)
		if err != nil {
			return err
		}
	}

	page.Timeout(5 * time.Second).WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)()
	return nil
}

// setupPageAndNavigate opens a page, performs all adaptive actions including JS injection
func (b *Browser) setupPageAndNavigate(url string, timeout time.Duration, headers []string, jsCodes []string) (*rod.Page, *headlessNetworkTracker, error) {
	page, err := b.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, nil, err
	}

	networkTracker := newHeadlessNetworkTracker()
	if err := b.navigateExistingPageWithArtifacts(page, url, timeout, headers, jsCodes, networkTracker); err != nil {
		return page, networkTracker, err
	}

	return page, networkTracker, nil
}

type headlessBrowserHeaderOverrides struct {
	ExtraHeaders    []string
	UserAgent       string
	AcceptLanguage  string
	SecCHUA         string
	SecCHUAMobile   string
	SecCHUAPlatform string
}

func parseHeadlessBrowserHeaders(headers []string) headlessBrowserHeaderOverrides {
	overrides := headlessBrowserHeaderOverrides{
		ExtraHeaders:   []string{},
		AcceptLanguage: defaultHeadlessAcceptLanguage,
	}

	for _, header := range headers {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			continue
		}

		key := strings.TrimSpace(headerParts[0])
		value := strings.TrimSpace(headerParts[1])
		if key == "" || value == "" {
			continue
		}

		switch {
		case strings.EqualFold(key, "User-Agent"):
			overrides.UserAgent = value
		case strings.EqualFold(key, "Accept-Language"):
			overrides.AcceptLanguage = value
		case strings.EqualFold(key, "Sec-CH-UA"):
			overrides.SecCHUA = value
		case strings.EqualFold(key, "Sec-CH-UA-Mobile"):
			overrides.SecCHUAMobile = value
		case strings.EqualFold(key, "Sec-CH-UA-Platform"):
			overrides.SecCHUAPlatform = value
		default:
			overrides.ExtraHeaders = append(overrides.ExtraHeaders, key, value)
		}
	}

	return overrides
}

func (b *Browser) applyHeadlessBrowserOverrides(page *rod.Page, overrides headlessBrowserHeaderOverrides) error {
	userAgent := strings.TrimSpace(overrides.UserAgent)
	if userAgent == "" {
		userAgent = b.defaultUserAgent
	}
	if userAgent == "" {
		userAgent = fallbackDesktopChromeUserAgent
	}

	acceptLanguage := strings.TrimSpace(overrides.AcceptLanguage)
	if acceptLanguage == "" {
		acceptLanguage = defaultHeadlessAcceptLanguage
	}

	if err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent:         userAgent,
		AcceptLanguage:    acceptLanguage,
		Platform:          browserNavigatorPlatform(userAgent, overrides.SecCHUAPlatform),
		UserAgentMetadata: buildDesktopChromeUserAgentMetadata(userAgent, overrides),
	}); err != nil {
		return err
	}

	if len(overrides.ExtraHeaders) > 0 {
		_, err := page.SetExtraHeaders(overrides.ExtraHeaders)
		return err
	}

	return nil
}

func normalizeHeadlessUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return ""
	}

	return strings.ReplaceAll(userAgent, "HeadlessChrome/", "Chrome/")
}

func buildDesktopChromeUserAgentMetadata(userAgent string, overrides headlessBrowserHeaderOverrides) *proto.EmulationUserAgentMetadata {
	majorVersion := chromeMajorVersion(userAgent)
	if majorVersion == "" {
		majorVersion = "128"
	}
	fullVersion := chromeFullVersion(userAgent)
	if fullVersion == "" {
		fullVersion = majorVersion + ".0.0.0"
	}
	brands := parseSecCHUABrands(overrides.SecCHUA)
	if len(brands) == 0 {
		brands = []*proto.EmulationUserAgentBrandVersion{
			{Brand: "Chromium", Version: majorVersion},
			{Brand: "Not A(Brand", Version: "99"},
		}
	}
	fullVersionList := make([]*proto.EmulationUserAgentBrandVersion, 0, len(brands))
	for _, brand := range brands {
		version := brand.Version
		if brand.Brand != "Not A(Brand" && !strings.Contains(version, ".") {
			version = fullVersion
		}
		fullVersionList = append(fullVersionList, &proto.EmulationUserAgentBrandVersion{
			Brand:   brand.Brand,
			Version: version,
		})
	}
	platform := browserClientHintsPlatform(userAgent, overrides.SecCHUAPlatform)
	mobile := strings.EqualFold(strings.TrimSpace(overrides.SecCHUAMobile), "?1") || strings.Contains(userAgent, " Mobile ")
	architecture, bitness := browserArchitecture(userAgent, platform, mobile)

	return &proto.EmulationUserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullVersionList,
		Platform:        platform,
		PlatformVersion: browserPlatformVersion(platform),
		Architecture:    architecture,
		Model:           "",
		Mobile:          mobile,
		Bitness:         bitness,
	}
}

func chromeMajorVersion(userAgent string) string {
	matches := regexp.MustCompile(`Chrome/([0-9]+)`).FindStringSubmatch(userAgent)
	if len(matches) != 2 {
		return ""
	}

	return matches[1]
}

func chromeFullVersion(userAgent string) string {
	matches := regexp.MustCompile(`Chrome/([0-9]+(?:\.[0-9]+){0,3})`).FindStringSubmatch(userAgent)
	if len(matches) != 2 {
		return ""
	}

	return matches[1]
}

func parseSecCHUABrands(secCHUA string) []*proto.EmulationUserAgentBrandVersion {
	brands := []*proto.EmulationUserAgentBrandVersion{}
	for _, match := range regexp.MustCompile(`"([^"]+)";v="([^"]+)"`).FindAllStringSubmatch(secCHUA, -1) {
		if len(match) != 3 {
			continue
		}
		brands = append(brands, &proto.EmulationUserAgentBrandVersion{
			Brand:   normalizeClientHintBrand(match[1]),
			Version: match[2],
		})
	}

	return brands
}

func normalizeClientHintBrand(brand string) string {
	switch brand {
	case "Not;A=Brand", "Not_A Brand":
		return "Not A(Brand"
	default:
		return brand
	}
}

func browserNavigatorPlatform(userAgent string, secCHUAPlatform string) string {
	switch browserClientHintsPlatform(userAgent, secCHUAPlatform) {
	case "Windows":
		return "Win32"
	case "macOS":
		return "MacIntel"
	case "Android":
		return "Linux armv8l"
	default:
		return "Linux x86_64"
	}
}

func browserClientHintsPlatform(userAgent string, secCHUAPlatform string) string {
	platform := strings.Trim(strings.TrimSpace(secCHUAPlatform), `"`)
	if platform != "" {
		switch strings.ToLower(platform) {
		case "windows":
			return "Windows"
		case "macos", "mac os", "mac os x":
			return "macOS"
		case "android":
			return "Android"
		case "linux", "chrome os":
			return platform
		}
		return platform
	}

	switch {
	case strings.Contains(userAgent, "Windows NT"):
		return "Windows"
	case strings.Contains(userAgent, "Mac OS X"):
		return "macOS"
	case strings.Contains(userAgent, "Android"):
		return "Android"
	default:
		return "Linux"
	}
}

func browserPlatformVersion(platform string) string {
	switch platform {
	case "Windows":
		return "10.0.0"
	case "macOS":
		return "14.0.0"
	case "Android":
		return "10.0.0"
	default:
		return "6.0.0"
	}
}

func browserArchitecture(userAgent string, platform string, mobile bool) (string, string) {
	if mobile || platform == "Android" {
		return "", ""
	}
	if strings.Contains(userAgent, "arm64") || strings.Contains(userAgent, "aarch64") {
		return "arm", "64"
	}

	return "x86", "64"
}

func buildHeadlessStealthScript(acceptLanguage string) string {
	languages := headlessLanguages(acceptLanguage)
	if len(languages) == 0 {
		languages = []string{"en-US", "en"}
	}

	languagePayload, err := json.Marshal(languages)
	if err != nil {
		languagePayload = []byte(`["en-US","en"]`)
	}

	return fmt.Sprintf(`(() => {
  const defineGetter = (target, key, value) => {
    try {
      Object.defineProperty(target, key, { get: () => value, configurable: true });
    } catch {}
  };
  defineGetter(Navigator.prototype, "webdriver", undefined);
  defineGetter(Navigator.prototype, "languages", %s);
})();`, string(languagePayload))
}

func headlessLanguages(acceptLanguage string) []string {
	acceptLanguage = strings.TrimSpace(acceptLanguage)
	if acceptLanguage == "" {
		acceptLanguage = defaultHeadlessAcceptLanguage
	}

	languages := []string{}
	for _, part := range strings.Split(acceptLanguage, ",") {
		language := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if language == "" {
			continue
		}
		languages = append(languages, language)
	}

	return languages
}

// capturePageArtifacts waits for the page and returns rendered HTML, document title, and optional screenshot bytes.
func (b *Browser) capturePageArtifacts(page *rod.Page, networkTracker *headlessNetworkTracker, idle time.Duration, fullPage bool, captureScreenshot bool, waitForRuntimeReadiness bool) ([]byte, string, string, []NetworkRequest, error) {
	// Some pages can make Rod's load helper fail even after navigation and paint
	// succeeded. Continue and let the artifact reads below decide whether the page
	// is usable.
	_ = page.WaitLoad()
	_ = page.WaitIdle(idle)

	if waitForRuntimeReadiness {
		b.waitForHeadlessReadiness(page, networkTracker)
	}

	var screenshot []byte
	if captureScreenshot {
		var err error
		screenshot, err = page.Screenshot(fullPage, &proto.PageCaptureScreenshot{
			Format: proto.PageCaptureScreenshotFormatPng,
		})
		if err != nil {
			return nil, "", "", nil, err
		}
	}

	title := b.captureDocumentTitle(page)

	body, err := page.HTML()
	if err != nil {
		return screenshot, "", title, networkTracker.snapshot(), err
	}

	return screenshot, body, title, networkTracker.snapshot(), nil
}

func (b *Browser) captureDocumentTitle(page *rod.Page) string {
	output, err := page.Eval(`() => document.title || ""`)
	if err != nil {
		return ""
	}

	rawValue := fmt.Sprint(output.Value)
	var title string
	if err := json.Unmarshal([]byte(rawValue), &title); err == nil {
		return strings.TrimSpace(title)
	}

	return strings.TrimSpace(rawValue)
}

func (b *Browser) collectHeadlessFavicons(page *rod.Page, pageBody string, networkRequests []NetworkRequest) []HeadlessFavicon {
	const maxFavicons = 5

	candidates := b.collectDocumentFaviconCandidates(page)
	if len(candidates) == 0 {
		candidates = b.collectHTMLFaviconCandidates(page, pageBody)
	}
	candidates = prioritizeHeadlessFaviconCandidates(candidates)

	favicons := make([]HeadlessFavicon, 0, len(candidates))
	for _, candidate := range candidates {
		if len(favicons) >= maxFavicons {
			break
		}
		if favicon, ok := b.collectHeadlessFaviconFromNetwork(page, candidate, networkRequests); ok {
			favicons = append(favicons, favicon)
			continue
		}
		if favicon, ok := b.fetchHeadlessFavicon(page, candidate); ok {
			favicons = append(favicons, favicon)
		}
	}

	return favicons
}

func (b *Browser) collectDocumentFaviconCandidates(page *rod.Page) []headlessFaviconCandidate {
	output, err := page.Eval(`() => {
const candidates = [];
const seen = new Set();
const addCandidate = (href) => {
  if (!href) return;
  try {
    const absoluteURL = new URL(href, document.baseURI || window.location.href).href;
    if (seen.has(absoluteURL)) return;
    seen.add(absoluteURL);
    candidates.push({ path: href, url: absoluteURL });
  } catch {}
};
for (const link of Array.from(document.querySelectorAll("link[rel][href]"))) {
  const rel = (link.getAttribute("rel") || "").toLowerCase();
  if (!rel.split(/\s+/).some((token) => token.includes("icon"))) continue;
  addCandidate(link.getAttribute("href"));
}
if (candidates.length === 0) {
  addCandidate("/favicon.ico");
}
return candidates.slice(0, 10);
}`)
	if err != nil {
		return nil
	}

	return decodeHeadlessFaviconCandidates(output)
}

func (b *Browser) collectHTMLFaviconCandidates(page *rod.Page, pageBody string) []headlessFaviconCandidate {
	currentURL := b.collectRuntimePageURL(page)
	if currentURL == "" || pageBody == "" {
		return nil
	}

	hrefs, baseHref, err := extractPotentialFavIconsURLs([]byte(pageBody))
	if err != nil {
		return nil
	}
	if len(hrefs) == 0 {
		hrefs = append(hrefs, "/favicon.ico")
	}

	baseURL, err := url.Parse(currentURL)
	if err != nil {
		return nil
	}
	if baseHref != "" {
		if parsedBaseHref, err := url.Parse(baseHref); err == nil {
			baseURL = baseURL.ResolveReference(parsedBaseHref)
		}
	}

	candidates := make([]headlessFaviconCandidate, 0, len(hrefs))
	seen := map[string]struct{}{}
	for _, href := range hrefs {
		href = strings.TrimSpace(href)
		if href == "" {
			continue
		}
		parsedHref, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolvedURL := baseURL.ResolveReference(parsedHref).String()
		if _, ok := seen[resolvedURL]; ok {
			continue
		}
		seen[resolvedURL] = struct{}{}
		candidates = append(candidates, headlessFaviconCandidate{
			Path: href,
			URL:  resolvedURL,
		})
	}

	return candidates
}

func decodeHeadlessFaviconCandidates(output *proto.RuntimeRemoteObject) []headlessFaviconCandidate {
	if output == nil {
		return nil
	}

	rawValue := fmt.Sprint(output.Value)
	var candidates []headlessFaviconCandidate
	if err := json.Unmarshal([]byte(rawValue), &candidates); err != nil {
		return nil
	}

	return candidates
}

func prioritizeHeadlessFaviconCandidates(candidates []headlessFaviconCandidate) []headlessFaviconCandidate {
	seen := map[string]struct{}{}
	deduped := make([]headlessFaviconCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.Path = strings.TrimSpace(candidate.Path)
		candidate.URL = strings.TrimSpace(candidate.URL)
		if candidate.URL == "" {
			continue
		}
		key := strings.ToLower(candidate.URL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, candidate)
	}

	sort.SliceStable(deduped, func(i, j int) bool {
		ai := strings.HasSuffix(strings.ToLower(deduped[i].Path), ".ico") || strings.HasSuffix(strings.ToLower(deduped[i].URL), ".ico")
		aj := strings.HasSuffix(strings.ToLower(deduped[j].Path), ".ico") || strings.HasSuffix(strings.ToLower(deduped[j].URL), ".ico")
		if ai == aj {
			return deduped[i].URL < deduped[j].URL
		}
		return ai && !aj
	})

	return deduped
}

func (b *Browser) collectHeadlessFaviconFromNetwork(page *rod.Page, candidate headlessFaviconCandidate, networkRequests []NetworkRequest) (HeadlessFavicon, bool) {
	const maxFaviconBytes = 1024 * 1024

	for _, request := range networkRequests {
		if request.RequestID == "" || request.StatusCode != http.StatusOK || !sameURLWithoutFragment(request.URL, candidate.URL) {
			continue
		}

		responseBody, err := proto.NetworkGetResponseBody{
			RequestID: proto.NetworkRequestID(request.RequestID),
		}.Call(page)
		if err != nil {
			continue
		}

		data := []byte(responseBody.Body)
		if responseBody.Base64Encoded {
			decoded, err := base64.StdEncoding.DecodeString(responseBody.Body)
			if err != nil {
				continue
			}
			data = decoded
		}
		if len(data) == 0 || len(data) > maxFaviconBytes {
			continue
		}

		return HeadlessFavicon{
			Path: candidate.Path,
			URL:  request.URL,
			Data: data,
		}, true
	}

	return HeadlessFavicon{}, false
}

func (b *Browser) fetchHeadlessFavicon(page *rod.Page, candidate headlessFaviconCandidate) (HeadlessFavicon, bool) {
	const maxFaviconBytes = 1024 * 1024

	output, err := page.Timeout(10*time.Second).Eval(`async (candidate) => {
const maxBytes = candidate.maxBytes;
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), 8000);
try {
  const response = await fetch(candidate.url, {
    credentials: "include",
    cache: "force-cache",
    signal: controller.signal
  });
  if (!response.ok) return null;
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (contentLength > maxBytes) return null;
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength === 0 || buffer.byteLength > maxBytes) return null;
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return {
    path: candidate.path,
    url: response.url || candidate.url,
    dataBase64: btoa(binary)
  };
} catch {
  return null;
} finally {
  clearTimeout(timer);
}
}`, map[string]interface{}{
		"path":     candidate.Path,
		"url":      candidate.URL,
		"maxBytes": maxFaviconBytes,
	})
	if err != nil || output == nil {
		return HeadlessFavicon{}, false
	}

	rawValue := fmt.Sprint(output.Value)
	if rawValue == "" || rawValue == "null" {
		return HeadlessFavicon{}, false
	}

	var payload headlessFaviconPayload
	if err := json.Unmarshal([]byte(rawValue), &payload); err != nil || payload.DataBase64 == "" {
		return HeadlessFavicon{}, false
	}
	data, err := base64.StdEncoding.DecodeString(payload.DataBase64)
	if err != nil || len(data) == 0 || len(data) > maxFaviconBytes {
		return HeadlessFavicon{}, false
	}

	return HeadlessFavicon{
		Path: payload.Path,
		URL:  payload.URL,
		Data: data,
	}, true
}

func sameURLWithoutFragment(left string, right string) bool {
	leftURL, err := url.Parse(left)
	if err != nil {
		return false
	}
	rightURL, err := url.Parse(right)
	if err != nil {
		return false
	}
	leftURL.Fragment = ""
	rightURL.Fragment = ""
	return strings.EqualFold(leftURL.String(), rightURL.String())
}

func (b *Browser) collectRuntimePageURL(page *rod.Page) string {
	output, err := page.Eval(`() => window.location.href`)
	if err != nil {
		return ""
	}

	rawValue := fmt.Sprint(output.Value)
	var pageURL string
	if err := json.Unmarshal([]byte(rawValue), &pageURL); err != nil {
		pageURL = rawValue
	}

	return strings.TrimSpace(pageURL)
}

func (b *Browser) waitForHeadlessReadiness(page *rod.Page, networkTracker *headlessNetworkTracker) {
	if networkTracker == nil {
		return
	}

	pageOrigin := b.collectRuntimePageOrigin(page)
	deadline := time.Now().Add(headlessReadinessTimeout)

	for time.Now().Before(deadline) {
		body, _ := page.HTML()
		networkRequests := networkTracker.snapshot()
		scriptCandidates := sameOriginScriptCandidates(body, networkRequests, pageOrigin)

		if len(scriptCandidates) > 0 && allScriptCandidatesCompleted(scriptCandidates, networkRequests) {
			return
		}

		quiet := networkTracker.quietFor(headlessReadinessQuietDuration)
		if quiet && !hasPendingSameOriginScripts(networkRequests, pageOrigin) {
			if shouldStopHeadlessReadiness(networkRequests, scriptCandidates, pageOrigin, b.hasHydratedAppRoot(page)) {
				return
			}
		}

		time.Sleep(headlessReadinessPollInterval)
	}
}

func shouldStopHeadlessReadiness(networkRequests []NetworkRequest, scriptCandidates []string, pageOrigin string, hydratedAppRoot bool) bool {
	return len(scriptCandidates) > 0 || hydratedAppRoot || onlyThirdPartyChallengeRequestsPending(networkRequests, pageOrigin)
}

func (b *Browser) hasHydratedAppRoot(page *rod.Page) bool {
	output, err := page.Eval(`() => {
const roots = [
  document.querySelector("#root"),
  document.querySelector("#app"),
  document.querySelector("[data-reactroot]")
].filter(Boolean);
return roots.some((root) => root.children.length > 0 || (root.textContent || "").trim().length > 20);
}`)
	if err != nil {
		return false
	}

	rawValue := fmt.Sprint(output.Value)
	var hydrated bool
	if err := json.Unmarshal([]byte(rawValue), &hydrated); err != nil {
		return rawValue == "true"
	}

	return hydrated
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

func (b *Browser) detectRuntimeTechnologies(page *rod.Page, networkRequests []NetworkRequest, pageBody string, wappalyzerClient *wappalyzer.Wappalyze) (map[string]wappalyzer.AppInfo, *RuntimeTechnologyDetectionMetrics) {
	startedAt := time.Now()
	technologies := map[string]wappalyzer.AppInfo{}
	metrics := &RuntimeTechnologyDetectionMetrics{
		Enabled:             true,
		PhaseDurationsMs:    map[string]int64{},
		NetworkRequestCount: len(networkRequests),
	}
	defer func() {
		metrics.DurationMs = time.Since(startedAt).Milliseconds()
		metrics.MatchedTechnologyCount = len(technologies)
		if metrics.StopReason == "" {
			metrics.StopReason = "completed"
		}
	}()

	if wappalyzerClient == nil {
		metrics.StopReason = "missing_wappalyzer_client"
		return technologies, metrics
	}

	phaseStartedAt := time.Now()
	addHeadlessBodyTechnologies(technologies, wappalyzerClient, pageBody)
	metrics.PhaseDurationsMs["headless_body_match"] = time.Since(phaseStartedAt).Milliseconds()

	originalFingerprints := wappalyzerClient.GetFingerprints()
	if originalFingerprints == nil {
		metrics.StopReason = "missing_fingerprints"
		return technologies, metrics
	}
	metrics.AppFingerprintCount = len(originalFingerprints.Apps)
	matchedRuntimeVersions := map[string]string{}

	phaseStartedAt = time.Now()
	pageOrigin := b.collectRuntimePageOrigin(page)
	metrics.PhaseDurationsMs["page_origin"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.SameOriginRequestCount = countSameOriginRequests(networkRequests, pageOrigin)
	metrics.ScriptRequestCount = countRequestsByResourceType(networkRequests, "script")
	metrics.PendingSameOriginScriptCount = countPendingSameOriginScripts(networkRequests, pageOrigin)

	phaseStartedAt = time.Now()
	jsValues, jsPropertyPathCount := b.collectRuntimeJSValues(page, wappalyzerClient)
	metrics.PhaseDurationsMs["js_values"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.JSPropertyPathCount = jsPropertyPathCount
	metrics.JSValueCount = len(jsValues)

	phaseStartedAt = time.Now()
	domValues, domSelectorCount := b.collectRuntimeDOMValues(page, originalFingerprints)
	metrics.PhaseDurationsMs["dom_values"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.DOMSelectorCount = domSelectorCount
	metrics.DOMValueCount = len(domValues)

	phaseStartedAt = time.Now()
	browserCookies := b.collectRuntimeCookies(page)
	metrics.PhaseDurationsMs["cookies"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.CookieCount = len(browserCookies)

	phaseStartedAt = time.Now()
	for app, fingerprint := range originalFingerprints.Apps {
		version := ""
		matched := false

		for propertyPath, patternString := range fingerprint.JS {
			value, ok := jsValues[propertyPath]
			if !ok {
				continue
			}

			pattern, ok := parseRuntimePattern(patternString)
			if !ok {
				continue
			}

			metrics.RuleEvaluationCount++
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

		if ok, versionString := b.matchHeaderFingerprint(fingerprint, networkRequests, pageOrigin); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchScriptSrcFingerprint(fingerprint, networkRequests); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if !matched {
			continue
		}

		matchedRuntimeVersions[app] = moreSpecificVersion(matchedRuntimeVersions[app], version)
	}
	metrics.PhaseDurationsMs["cheap_rule_match"] = time.Since(phaseStartedAt).Milliseconds()

	phaseStartedAt = time.Now()
	scriptCollection := b.collectRuntimeScriptResourceBodies(page, networkRequests, pageOrigin, pageBody)
	metrics.PhaseDurationsMs["script_bodies"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.SameOriginScriptCandidateCount = scriptCollection.CandidateCount
	metrics.ScriptBodiesCaptured = scriptCollection.CapturedCount
	metrics.ScriptBodiesFetched = scriptCollection.FetchedCount
	metrics.ScriptBodyBytes = scriptCollection.Bytes

	phaseStartedAt = time.Now()
	cssCollection := b.collectRuntimeResourceBodiesWithURLs(page, networkRequests, pageOrigin, isLikelyCSSRequest)
	metrics.PhaseDurationsMs["css_bodies"] = time.Since(phaseStartedAt).Milliseconds()
	metrics.CSSBodiesCaptured = len(cssCollection.Bodies)
	metrics.CSSBodyBytes = cssCollection.Bytes

	phaseStartedAt = time.Now()
	for app, fingerprint := range originalFingerprints.Apps {
		version := ""
		matched := false

		if ok, versionString := b.matchScriptBodyFingerprint(fingerprint, scriptCollection.Bodies); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if ok, versionString := b.matchCSSFingerprint(fingerprint, cssCollection.Bodies); ok {
			matched = true
			version = moreSpecificVersion(version, versionString)
		}

		if !matched {
			continue
		}

		matchedRuntimeVersions[app] = moreSpecificVersion(matchedRuntimeVersions[app], version)
	}
	metrics.PhaseDurationsMs["body_rule_match"] = time.Since(phaseStartedAt).Milliseconds()

	phaseStartedAt = time.Now()
	for app, version := range matchedRuntimeVersions {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, app, version)
	}
	metrics.PhaseDurationsMs["catalog_match_apply"] = time.Since(phaseStartedAt).Milliseconds()

	if b.hasReactRuntimeDOMInternalEvidence(page) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "React", "")
	}
	if b.hasTanStackRouterRuntimeEvidence(page) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "TanStack Router", "")
	}

	phaseStartedAt = time.Now()
	addRuntimeBundleTechnologies(technologies, wappalyzerClient, originalFingerprints, pageBody, networkRequests, scriptCollection.Bodies)
	metrics.PhaseDurationsMs["bundle_heuristics"] = time.Since(phaseStartedAt).Milliseconds()

	return technologies, metrics
}

func addHeadlessBodyTechnologies(technologies map[string]wappalyzer.AppInfo, wappalyzerClient *wappalyzer.Wappalyze, pageBody string) {
	if pageBody == "" {
		return
	}

	for match, data := range wappalyzerClient.FingerprintWithInfo(map[string][]string{}, []byte(pageBody)) {
		technologies[match] = data
	}
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
	if hasTanStackRouterBundleEvidence(pageBody, scriptBodies) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "TanStack Router", "")
	}
	if hasTanStackStartBundleEvidence(pageBody, scriptBodies) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "TanStack Start", "")
	}
	if hasTanStackQueryBundleEvidence(scriptBodies) {
		addRuntimeTechnology(technologies, wappalyzerClient, originalFingerprints, "TanStack Query", "")
	}
}

func (b *Browser) collectRuntimeJSValues(page *rod.Page, wappalyzerClient *wappalyzer.Wappalyze) (map[string]string, int) {
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

	return values, len(propertyPaths)
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

func (b *Browser) collectRuntimeDOMValues(page *rod.Page, fingerprints *wappalyzer.Fingerprints) (map[string]runtimeDOMValue, int) {
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

	return values, len(specs)
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
	cookies := b.collectRuntimeDocumentCookies(page)
	pageOrigin := b.collectRuntimePageOrigin(page)
	if pageOrigin == "" {
		return cookies
	}

	browserCookies, err := page.Cookies([]string{pageOrigin})
	if err != nil {
		return cookies
	}
	for _, cookie := range browserCookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		cookies[strings.ToLower(cookie.Name)] = strings.ToLower(cookie.Value)
	}

	return cookies
}

func (b *Browser) collectRuntimeDocumentCookies(page *rod.Page) map[string]string {
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

func (b *Browser) collectRuntimeResourceBodiesWithURLs(page *rod.Page, networkRequests []NetworkRequest, pageOrigin string, predicate func(NetworkRequest) bool) runtimeBodyCollection {
	const (
		maxResources      = 20
		maxResourceBytes  = 2 * 1024 * 1024
		maxTotalBodyBytes = 8 * 1024 * 1024
	)

	bodies := make([]string, 0)
	seen := map[string]struct{}{}
	captured := map[string]struct{}{}
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
		captured[strings.ToLower(request.URL)] = struct{}{}
		totalBytes += len(body)
	}

	return runtimeBodyCollection{
		Bodies:       bodies,
		CapturedURLs: captured,
		Bytes:        totalBytes,
	}
}

func (b *Browser) collectRuntimeScriptResourceBodies(page *rod.Page, networkRequests []NetworkRequest, pageOrigin string, pageBody string) runtimeScriptBodyCollection {
	candidates := sameOriginScriptCandidates(pageBody, networkRequests, pageOrigin)
	networkCollection := b.collectRuntimeResourceBodiesWithURLs(page, networkRequests, pageOrigin, isLikelyScriptRequest)
	fallbackCollection := fetchSameOriginScriptBodies(pageBody, networkRequests, pageOrigin, networkCollection.CapturedURLs)
	bodies := append(networkCollection.Bodies, fallbackCollection.Bodies...)

	return runtimeScriptBodyCollection{
		Bodies:         bodies,
		CandidateCount: len(candidates),
		CapturedCount:  len(networkCollection.Bodies),
		FetchedCount:   len(fallbackCollection.Bodies),
		Bytes:          networkCollection.Bytes + fallbackCollection.Bytes,
	}
}

func fetchSameOriginScriptBodies(pageBody string, networkRequests []NetworkRequest, pageOrigin string, capturedURLs map[string]struct{}) runtimeBodyCollection {
	const (
		maxFetches        = 10
		maxResourceBytes  = 2 * 1024 * 1024
		maxTotalBodyBytes = 8 * 1024 * 1024
		maxConcurrency    = 4
		totalFetchTimeout = 8 * time.Second
		requestTimeout    = 3 * time.Second
	)

	scriptCandidates := sameOriginScriptCandidates(pageBody, networkRequests, pageOrigin)
	if len(scriptCandidates) == 0 {
		return runtimeBodyCollection{}
	}

	fetchURLs := make([]string, 0, maxFetches)
	for _, scriptURL := range scriptCandidates {
		if len(fetchURLs) >= maxFetches {
			break
		}
		if _, ok := capturedURLs[strings.ToLower(scriptURL)]; ok {
			continue
		}
		fetchURLs = append(fetchURLs, scriptURL)
	}
	if len(fetchURLs) == 0 {
		return runtimeBodyCollection{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), totalFetchTimeout)
	defer cancel()

	client := &http.Client{Timeout: requestTimeout}
	bodies := make([]string, 0)
	captured := map[string]struct{}{}
	totalBytes := 0
	type fetchResult struct {
		url  string
		body []byte
	}
	results := make(chan fetchResult, len(fetchURLs))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

launchLoop:
	for _, scriptURL := range fetchURLs {
		select {
		case <-ctx.Done():
			break launchLoop
		default:
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		request.Header.Set("Accept", "application/javascript,text/javascript,*/*;q=0.8")
		request.Header.Set("Referer", pageOrigin+"/")
		request.Header.Set("User-Agent", fallbackDesktopChromeUserAgent)

		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			response, err := client.Do(request)
			if err != nil {
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResourceBytes+1))
			_ = response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusOK || len(body) == 0 || len(body) > maxResourceBytes {
				return
			}

			select {
			case results <- fetchResult{url: scriptURL, body: body}:
			case <-ctx.Done():
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if totalBytes >= maxTotalBodyBytes {
			cancel()
			continue
		}
		if totalBytes+len(result.body) > maxTotalBodyBytes {
			continue
		}
		bodies = append(bodies, strings.ToLower(string(result.body)))
		captured[strings.ToLower(result.url)] = struct{}{}
		totalBytes += len(result.body)
	}

	return runtimeBodyCollection{
		Bodies:       bodies,
		CapturedURLs: captured,
		Bytes:        totalBytes,
	}
}

func isSameOriginRequest(rawRequestURL string, pageOrigin string) bool {
	requestURL, err := url.Parse(rawRequestURL)
	if err != nil || requestURL.Scheme == "" || requestURL.Host == "" {
		return false
	}

	requestOrigin := strings.ToLower(requestURL.Scheme + "://" + requestURL.Host)
	return requestOrigin == pageOrigin
}

func countRequestsByResourceType(networkRequests []NetworkRequest, resourceType string) int {
	count := 0
	for _, request := range networkRequests {
		if strings.EqualFold(request.ResourceType, resourceType) {
			count++
		}
	}
	return count
}

func countSameOriginRequests(networkRequests []NetworkRequest, pageOrigin string) int {
	if pageOrigin == "" {
		return 0
	}

	count := 0
	for _, request := range networkRequests {
		if isSameOriginRequest(request.URL, pageOrigin) {
			count++
		}
	}
	return count
}

func countPendingSameOriginScripts(networkRequests []NetworkRequest, pageOrigin string) int {
	if pageOrigin == "" {
		return 0
	}

	count := 0
	for _, request := range networkRequests {
		if strings.EqualFold(request.ResourceType, "script") && request.StatusCode <= 0 && isSameOriginRequest(request.URL, pageOrigin) {
			count++
		}
	}
	return count
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

func sameOriginScriptCandidates(pageBody string, networkRequests []NetworkRequest, pageOrigin string) []string {
	candidates := make([]string, 0)
	seen := map[string]struct{}{}

	addCandidate := func(rawURL string) {
		normalizedURL, ok := normalizeSameOriginURL(rawURL, pageOrigin)
		if !ok || !isLikelyJavaScriptURL(normalizedURL) {
			return
		}
		if _, ok := seen[normalizedURL]; ok {
			return
		}
		seen[normalizedURL] = struct{}{}
		candidates = append(candidates, normalizedURL)
	}

	for _, match := range scriptSrcPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		addCandidate(match[1])
	}

	for _, match := range modulePreloadHrefPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		addCandidate(match[1])
	}

	for _, match := range dynamicImportPattern.FindAllStringSubmatch(pageBody, -1) {
		if len(match) < 2 {
			continue
		}
		addCandidate(match[1])
	}

	for _, request := range networkRequests {
		if isLikelyScriptRequest(request) {
			addCandidate(request.URL)
		}
	}

	return candidates
}

func normalizeSameOriginURL(rawRequestURL string, pageOrigin string) (string, bool) {
	if pageOrigin == "" || rawRequestURL == "" {
		return "", false
	}

	baseURL, err := url.Parse(pageOrigin)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return "", false
	}

	requestURL, err := url.Parse(rawRequestURL)
	if err != nil {
		return "", false
	}
	if requestURL.Scheme == "" && requestURL.Host == "" {
		requestURL = baseURL.ResolveReference(requestURL)
	}
	if requestURL.Scheme == "" || requestURL.Host == "" {
		return "", false
	}
	if strings.ToLower(requestURL.Scheme+"://"+requestURL.Host) != pageOrigin {
		return "", false
	}

	return requestURL.String(), true
}

func normalizeNetworkHeaders(headers proto.NetworkHeaders) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		headerName := strings.ToLower(strings.TrimSpace(name))
		if headerName == "" {
			continue
		}
		normalized[headerName] = strings.ToLower(strings.TrimSpace(value.String()))
	}

	return normalized
}

func isLikelyJavaScriptURL(rawRequestURL string) bool {
	parsedURL, err := url.Parse(rawRequestURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsedURL.Path)
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

func allScriptCandidatesCompleted(scriptCandidates []string, networkRequests []NetworkRequest) bool {
	completed := map[string]struct{}{}
	for _, request := range networkRequests {
		if request.StatusCode == http.StatusOK && isLikelyScriptRequest(request) {
			completed[strings.ToLower(request.URL)] = struct{}{}
		}
	}

	for _, scriptURL := range scriptCandidates {
		if _, ok := completed[strings.ToLower(scriptURL)]; !ok {
			return false
		}
	}

	return true
}

func hasPendingSameOriginScripts(networkRequests []NetworkRequest, pageOrigin string) bool {
	for _, request := range networkRequests {
		if request.StatusCode != -1 || !isLikelyScriptRequest(request) {
			continue
		}
		if pageOrigin == "" || isSameOriginRequest(request.URL, pageOrigin) {
			return true
		}
	}

	return false
}

func onlyThirdPartyChallengeRequestsPending(networkRequests []NetworkRequest, pageOrigin string) bool {
	hasPending := false
	for _, request := range networkRequests {
		if request.StatusCode != -1 {
			continue
		}
		hasPending = true
		if isSameOriginRequest(request.URL, pageOrigin) && !isCloudflareChallengeURL(request.URL) {
			return false
		}
	}

	return hasPending
}

func isCloudflareChallengeURL(rawRequestURL string) bool {
	urlLower := strings.ToLower(rawRequestURL)
	return strings.Contains(urlLower, "/cdn-cgi/challenge-platform/") ||
		strings.Contains(urlLower, "challenges.cloudflare.com")
}

func hasReactBundleEvidence(scriptBodies []string) bool {
	for _, body := range scriptBodies {
		if hasReactPackageBannerEvidence(body) || hasReactRuntimeSymbolEvidence(body) {
			return true
		}
	}

	return false
}

func hasReactPackageBannerEvidence(body string) bool {
	if !strings.Contains(body, "@license react") {
		return false
	}

	return strings.Contains(body, "react.production.min.js") ||
		strings.Contains(body, "react-dom.production.min.js") ||
		strings.Contains(body, "react-jsx-runtime.production.min.js")
}

func hasReactRuntimeSymbolEvidence(body string) bool {
	normalizedBody := strings.ToLower(body)
	if !strings.Contains(normalizedBody, `symbol.for("react.`) &&
		!strings.Contains(normalizedBody, `symbol.for('react.`) &&
		!strings.Contains(normalizedBody, "symbol.for(`react.") {
		return false
	}

	markers := []string{
		"react.element",
		"react.transitional.element",
		"react.portal",
		"react.fragment",
		"react.strict_mode",
		"react.profiler",
		"react.consumer",
		"react.context",
		"react.forward_ref",
		"react.suspense",
		"react.memo",
		"react.lazy",
	}

	matchCount := 0
	for _, marker := range markers {
		if strings.Contains(normalizedBody, marker) {
			matchCount++
		}
	}

	return matchCount >= 5
}

func (b *Browser) hasReactRuntimeDOMInternalEvidence(page *rod.Page) bool {
	output, err := page.Eval(`() => {
const prefixes = ["__reactFiber$", "__reactProps$", "__reactContainer$"];
const selectors = ["body", "#root", "#app", "#__next", "body > div", "[data-reactroot]"];
const elements = new Set();
for (const selector of selectors) {
  for (const element of document.querySelectorAll(selector)) {
    elements.add(element);
  }
}
let visited = 0;
const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_ELEMENT);
while (visited < 500) {
  const element = walker.nextNode();
  if (!element) break;
  elements.add(element);
  visited++;
}
for (const element of elements) {
  if (Object.getOwnPropertyNames(element).some((name) => prefixes.some((prefix) => name.startsWith(prefix)))) {
    return true;
  }
}
return false;
}`)
	if err != nil {
		return false
	}

	return strings.EqualFold(fmt.Sprint(output.Value), "true")
}

func (b *Browser) hasTanStackRouterRuntimeEvidence(page *rod.Page) bool {
	output, err := page.Eval(`() => Boolean(window.__TSR_ROUTER__)`)
	if err != nil {
		return false
	}

	return strings.EqualFold(fmt.Sprint(output.Value), "true")
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

func hasTanStackRouterBundleEvidence(pageBody string, scriptBodies []string) bool {
	for _, body := range append([]string{pageBody}, scriptBodies...) {
		normalizedBody := strings.ToLower(body)
		if strings.Contains(normalizedBody, "$_tsr.router") && strings.Contains(normalizedBody, "tsr-scroll-restoration") {
			return true
		}
	}

	return false
}

func hasTanStackStartBundleEvidence(pageBody string, scriptBodies []string) bool {
	for _, body := range append([]string{pageBody}, scriptBodies...) {
		normalizedBody := strings.ToLower(body)
		if strings.Contains(normalizedBody, "$_tsr.router") && strings.Contains(normalizedBody, "tsr-stream-barrier") {
			return true
		}
	}

	return false
}

func hasTanStackQueryBundleEvidence(scriptBodies []string) bool {
	for _, body := range scriptBodies {
		normalizedBody := strings.ToLower(body)
		if strings.Contains(normalizedBody, "@tanstack/react-query") || strings.Contains(normalizedBody, "@tanstack/query-core") {
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

func (b *Browser) matchHeaderFingerprint(fingerprint *wappalyzer.Fingerprint, networkRequests []NetworkRequest, pageOrigin string) (bool, string) {
	if len(fingerprint.Headers) == 0 || len(networkRequests) == 0 {
		return false, ""
	}

	version := ""

	for _, request := range networkRequests {
		if pageOrigin != "" && !isSameOriginRequest(request.URL, pageOrigin) {
			continue
		}
		if len(request.ResponseHeaders) == 0 {
			continue
		}

		for headerName, patternString := range fingerprint.Headers {
			value, ok := request.ResponseHeaders[strings.ToLower(headerName)]
			if !ok {
				continue
			}
			if ok, versionString := evaluateRuntimePattern(patternString, value); ok {
				version = moreSpecificVersion(version, versionString)
				return true, version
			}
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
	pattern, ok := parseRuntimePattern(patternString)
	if !ok {
		return false, ""
	}

	valid, versionString := pattern.Evaluate(value)
	return valid && pattern.Confidence > 0, versionString
}

func parseRuntimePattern(patternString string) (*wappalyzer.ParsedPattern, bool) {
	if cachedValue, ok := runtimePatternCache.Load(patternString); ok {
		cached := cachedValue.(cachedRuntimePattern)
		return cached.pattern, cached.ok
	}

	pattern, err := wappalyzer.ParsePattern(patternString)
	cached := cachedRuntimePattern{
		pattern: pattern,
		ok:      err == nil,
	}
	actualValue, _ := runtimePatternCache.LoadOrStore(patternString, cached)
	actual := actualValue.(cachedRuntimePattern)

	return actual.pattern, actual.ok
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
