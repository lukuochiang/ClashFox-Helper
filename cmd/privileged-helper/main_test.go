package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newHandlerTestHelper() *helper {
	l := log.New(io.Discard, "", 0)
	return &helper{
		token: "test-token",
		log:   l,
		audit: l,
		policy: policy{
			AllowedUIDs:                []uint32{501},
			AllowedClientPathPrefixes:  []string{"/Applications/ClashFox.app/"},
			EnableCallerPathConstraint: true,
		},
		serviceLocks: map[string]*sync.Mutex{},
		rl:           map[string]*rateBucket{},
		breaker:      map[string]*breakerState{},
		rateConf: rateConfig{
			Window:           10 * time.Second,
			MaxRequests:      40,
			BreakerWindow:    60 * time.Second,
			BreakerThreshold: 8,
			BreakerTTL:       2 * time.Minute,
		},
	}
}

func withCaller(req *http.Request) *http.Request {
	ci := callerInfo{
		UID:  501,
		PID:  12345,
		Path: "/Applications/ClashFox.app/Contents/MacOS/ClashFox",
	}
	ctx := context.WithValue(req.Context(), callerKey, ci)
	return req.WithContext(ctx)
}

func TestParseProxyConfigOutput_MacOS12Style(t *testing.T) {
	in := []byte("Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n")
	enabled, host, port, err := parseProxyConfigOutput(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if enabled {
		t.Fatalf("expected disabled")
	}
	if host != "" {
		t.Fatalf("expected empty host, got %q", host)
	}
	if port != 0 {
		t.Fatalf("expected port 0, got %d", port)
	}
}

func TestParseProxyConfigOutput_Enabled(t *testing.T) {
	in := []byte("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n")
	enabled, host, port, err := parseProxyConfigOutput(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !enabled || host != "127.0.0.1" || port != 7890 {
		t.Fatalf("unexpected parse result enabled=%t host=%q port=%d", enabled, host, port)
	}
}

func TestParseAutoProxyDiscoveryOutput(t *testing.T) {
	enabled, err := parseAutoProxyDiscoveryOutput([]byte("Auto Proxy Discovery: On\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !enabled {
		t.Fatalf("expected enabled")
	}
	enabled, err = parseAutoProxyDiscoveryOutput([]byte("Auto Proxy Discovery: Off\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if enabled {
		t.Fatalf("expected disabled")
	}
}

func TestParseAutoProxyURLOutput(t *testing.T) {
	enabled, url, err := parseAutoProxyURLOutput([]byte("URL: http://127.0.0.1:6152/proxy.pac\nEnabled: Yes\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !enabled || url != "http://127.0.0.1:6152/proxy.pac" {
		t.Fatalf("unexpected result enabled=%t url=%q", enabled, url)
	}
	enabled, url, err = parseAutoProxyURLOutput([]byte("URL: \nEnabled: No\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if enabled || url != "" {
		t.Fatalf("unexpected result enabled=%t url=%q", enabled, url)
	}
}

func TestParseAutoProxyURLOutput_NullURL(t *testing.T) {
	enabled, url, err := parseAutoProxyURLOutput([]byte("URL: (null)\nEnabled: No\n"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if enabled || url != "" {
		t.Fatalf("unexpected result enabled=%t url=%q", enabled, url)
	}
}

func TestParseDefaultRouteInterface(t *testing.T) {
	out := []byte(`route to: default
destination: default
interface: en0
flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>`)
	iface := parseDefaultRouteInterface(out)
	if iface != "en0" {
		t.Fatalf("expected en0, got %q", iface)
	}
}

func TestParseNetworkServiceOrder(t *testing.T) {
	out := []byte(`An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)
`)
	got := parseNetworkServiceOrder(out)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Service != "Wi-Fi" || got[0].Device != "en0" {
		t.Fatalf("unexpected first entry: %+v", got[0])
	}
	if got[1].Service != "USB 10/100/1000 LAN" || got[1].Device != "en5" {
		t.Fatalf("unexpected second entry: %+v", got[1])
	}
}

func TestAllowedCommand_RouteDefaultOnly(t *testing.T) {
	bin, err := allowedCommand(cmdRoute, []string{"-n", "get", "default"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bin != "/sbin/route" {
		t.Fatalf("unexpected route bin: %q", bin)
	}
	if _, err := allowedCommand(cmdRoute, []string{"get", "default"}); err == nil {
		t.Fatalf("expected rejection for invalid route args")
	}
}

func TestAllowedCommand_NetworkSetupAutoProxyCommands(t *testing.T) {
	cases := [][]string{
		{"-setautoproxyurl", "Wi-Fi", "http://127.0.0.1/proxy.pac"},
		{"-setautoproxystate", "Wi-Fi", "off"},
		{"-setproxyautodiscovery", "Wi-Fi", "off"},
		{"-getautoproxyurl", "Wi-Fi"},
		{"-getproxyautodiscovery", "Wi-Fi"},
	}
	for _, args := range cases {
		if _, err := allowedCommand(cmdNetworkSetup, args); err != nil {
			t.Fatalf("expected command allowed for args=%v, err=%v", args, err)
		}
	}
}

func TestResolveProxyPorts_SplitAndMixed(t *testing.T) {
	// Split-port style from config: port + socks-port (+ mixed-port should not override explicit values).
	web, sec, socks, err := resolveProxyPorts(setProxyReq{
		Port:           7890,
		SOCKSPortKebab: 7891,
		MixedPortKebab: 7893,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if web != 7890 || sec != 7890 || socks != 7891 {
		t.Fatalf("unexpected split ports web=%d sec=%d socks=%d", web, sec, socks)
	}

	// Mixed-port only.
	web, sec, socks, err = resolveProxyPorts(setProxyReq{MixedPort: 7893})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if web != 7893 || sec != 7893 || socks != 7893 {
		t.Fatalf("unexpected mixed ports web=%d sec=%d socks=%d", web, sec, socks)
	}
}

func TestResolveProxyPorts_Conflict(t *testing.T) {
	_, _, _, err := resolveProxyPorts(setProxyReq{
		HTTPPort:      7890,
		HTTPPortKebab: 7891,
	})
	if err == nil {
		t.Fatalf("expected conflict error")
	}
}

func TestSecureTokenMatch(t *testing.T) {
	if !secureTokenMatch("abc123", "abc123") {
		t.Fatalf("expected token match")
	}
	badCases := [][2]string{
		{"abc123", "abc124"},
		{"abc123", ""},
		{"", "abc123"},
		{"abc123", " abc123x "},
	}
	for _, tc := range badCases {
		if secureTokenMatch(tc[0], tc[1]) {
			t.Fatalf("expected mismatch: %q vs %q", tc[0], tc[1])
		}
	}
}

func TestPrepareSocketPath(t *testing.T) {
	tmpDir := t.TempDir()

	socketFile := filepath.Join(tmpDir, "helper.sock")
	if err := os.WriteFile(socketFile, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := prepareSocketPath(socketFile); err == nil {
		t.Fatalf("expected error for non-socket path")
	}

	missing := filepath.Join(tmpDir, "missing.sock")
	if err := prepareSocketPath(missing); err != nil {
		t.Fatalf("expected nil for missing socket path, got %v", err)
	}
}

func TestPolicyClientUIDs(t *testing.T) {
	got := policyClientUIDs(policy{AllowedUIDs: []uint32{0, 502, 501, 0, 501}})
	if len(got) != 2 {
		t.Fatalf("unexpected uid list length: %v", got)
	}
	if got[0] != 501 || got[1] != 502 {
		t.Fatalf("unexpected uid order/content: %v", got)
	}
}

func TestEnsureToken_RegeneratesWhenEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write token fixture: %v", err)
	}
	got, err := ensureToken(p)
	if err != nil {
		t.Fatalf("ensureToken failed: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("expected 64-char token, got %q", got)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	if got != string(bytesTrimSpace(raw)) {
		t.Fatalf("token mismatch between return and file")
	}
}

func TestLoadStateBestEffort_MigratesLegacyFormat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	legacy := `{
  "proxy": {"service":"Wi-Fi","host":"127.0.0.1","port":7890,"enabled":true},
  "dns": {"service":"Wi-Fi","servers":["1.1.1.1","8.8.8.8"]},
  "tun": {"ipForward":true,"pfEnabled":false}
}`
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	logger := log.New(io.Discard, "", 0)
	s := loadStateBestEffort(p, logger)
	if len(s.Proxy) != 1 || len(s.DNS) != 1 || s.TUN == nil {
		t.Fatalf("unexpected migrated state: %+v", s)
	}
	proxy := s.Proxy["Wi-Fi"]
	if !proxy.Enabled || proxy.Host != "127.0.0.1" || proxy.Port != 7890 {
		t.Fatalf("unexpected proxy state: %+v", proxy)
	}
	dns := s.DNS["Wi-Fi"]
	if len(dns.Servers) != 2 || dns.Servers[0] != "1.1.1.1" || dns.Servers[1] != "8.8.8.8" {
		t.Fatalf("unexpected dns state: %+v", dns)
	}
	if !s.TUN.IPForward || s.TUN.PFEnabled {
		t.Fatalf("unexpected tun state: %+v", s.TUN)
	}
}

func bytesTrimSpace(b []byte) string {
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return string(b[i:j])
}

func TestDecodeJSON_RejectsTrailingData(t *testing.T) {
	var v struct {
		Service string `json:"service"`
	}
	err := decodeJSON(strings.NewReader(`{"service":"Wi-Fi"}{"x":1}`), &v)
	if err == nil {
		t.Fatalf("expected error for trailing json data")
	}
}

func TestDecodeJSON_RejectsUnknownField(t *testing.T) {
	var v struct {
		Service string `json:"service"`
	}
	err := decodeJSON(strings.NewReader(`{"service":"Wi-Fi","extra":1}`), &v)
	if err == nil {
		t.Fatalf("expected error for unknown field")
	}
}

func TestDeriveCoreRuntimePaths(t *testing.T) {
	data, bin, conf, logPath, err := deriveCoreRuntimePaths("/Users/alice")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if data != "/Users/alice/Library/Application Support/ClashFox/data" {
		t.Fatalf("unexpected data path: %q", data)
	}
	if bin != "/Users/alice/Library/Application Support/ClashFox/core/mihomo" {
		t.Fatalf("unexpected binary path: %q", bin)
	}
	if conf != "/Users/alice/Library/Application Support/ClashFox/data/default.yaml" {
		t.Fatalf("unexpected config path: %q", conf)
	}
	if logPath != "/Users/alice/Library/Application Support/ClashFox/logs/clashfox.log" {
		t.Fatalf("unexpected log path: %q", logPath)
	}
}

func TestEnsureDebugConfig_DefaultCreate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "debug-config.json")
	cfg, err := ensureDebugConfig(p, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("ensureDebugConfig create failed: %v", err)
	}
	if cfg.EnableConsoleCurl {
		t.Fatalf("expected default enableConsoleCurl=false")
	}
	if len(cfg.ExtraAllowedCoreBinaries) != 0 || len(cfg.ExtraAllowedClientPathPrefixes) != 0 {
		t.Fatalf("expected default empty debug config: %+v", cfg)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected debug config file created: %v", err)
	}
}

func TestEnsureDebugConfig_NormalizeAndApply(t *testing.T) {
	p := filepath.Join(t.TempDir(), "debug-config.json")
	raw := `{
  "extraAllowedCoreBinaries": ["/tmp/mihomo-dev", " relative/path ", "/tmp/mihomo-dev"],
  "extraAllowedClientPathPrefixes": ["/usr/bin/curl", "bin/client"],
  "enableConsoleCurl": true
}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatalf("write debug config: %v", err)
	}
	cfg, err := ensureDebugConfig(p, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("ensureDebugConfig parse failed: %v", err)
	}
	if len(cfg.ExtraAllowedCoreBinaries) != 1 || cfg.ExtraAllowedCoreBinaries[0] != "/tmp/mihomo-dev" {
		t.Fatalf("unexpected extra core binaries: %+v", cfg.ExtraAllowedCoreBinaries)
	}
	if len(cfg.ExtraAllowedClientPathPrefixes) != 1 || cfg.ExtraAllowedClientPathPrefixes[0] != "/usr/bin/curl" {
		t.Fatalf("unexpected extra client prefixes: %+v", cfg.ExtraAllowedClientPathPrefixes)
	}

	oldBins := append([]string(nil), allowedCoreBinaries...)
	defer func() {
		allowedCoreBinaries = oldBins
	}()

	pol := policy{
		AllowedUIDs:                []uint32{501},
		AllowedClientPathPrefixes:  []string{"/Applications/ClashFox.app/"},
		EnableCallerPathConstraint: true,
	}
	allowedCoreBinaries = []string{"/base/mihomo"}
	applyDebugConfig(&pol, cfg, log.New(io.Discard, "", 0))

	if !containsString(pol.AllowedClientPathPrefixes, "/usr/bin/curl") {
		t.Fatalf("expected /usr/bin/curl in allowed client prefixes: %+v", pol.AllowedClientPathPrefixes)
	}
	if !containsString(allowedCoreBinaries, "/tmp/mihomo-dev") {
		t.Fatalf("expected extra binary allowed: %+v", allowedCoreBinaries)
	}
}

func TestDeriveCoreRuntimePaths_RejectsNonUserHome(t *testing.T) {
	if _, _, _, _, err := deriveCoreRuntimePaths("/Library/Application Support"); err == nil {
		t.Fatalf("expected rejection for non /Users home")
	}
	if _, _, _, _, err := deriveCoreRuntimePaths("/var/root"); err == nil {
		t.Fatalf("expected rejection for /var/root")
	}
	if _, _, _, _, err := deriveCoreRuntimePaths(""); err == nil {
		t.Fatalf("expected rejection for empty home")
	}
}

func TestPathWithinBase(t *testing.T) {
	if !pathWithinBase("/Users/alice/Library/Application Support/ClashFox/core", "/Users/alice/Library/Application Support/ClashFox") {
		t.Fatalf("expected path within base")
	}
	if pathWithinBase("/Library/Application Support/ClashFox/core", "/Users/alice/Library/Application Support/ClashFox") {
		t.Fatalf("expected path outside base")
	}
}

func containsString(items []string, target string) bool {
	for _, it := range items {
		if it == target {
			return true
		}
	}
	return false
}

func TestValidateCoreRuntimePaths(t *testing.T) {
	oldHome := coreUserHomeDir
	oldData := coreDataDir
	oldBin := coreManagedBinaryPath
	oldCfg := coreConfigPath
	oldLog := coreLogPath
	t.Cleanup(func() {
		coreUserHomeDir = oldHome
		coreDataDir = oldData
		coreManagedBinaryPath = oldBin
		coreConfigPath = oldCfg
		coreLogPath = oldLog
	})

	coreUserHomeDir = "/Users/alice"
	coreDataDir = "/Users/alice/Library/Application Support/ClashFox/data"
	coreManagedBinaryPath = "/Users/alice/Library/Application Support/ClashFox/core/mihomo"
	coreConfigPath = "/Users/alice/Library/Application Support/ClashFox/data/default.yaml"
	coreLogPath = "/Users/alice/Library/Application Support/ClashFox/logs/clashfox.log"
	if err := validateCoreRuntimePaths(); err != nil {
		t.Fatalf("expected valid runtime paths, got %v", err)
	}

	coreLogPath = "/tmp/clashfox.log"
	if err := validateCoreRuntimePaths(); err == nil {
		t.Fatalf("expected invalid runtime path policy")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "atomic.txt")
	if err := writeFileAtomic(p, []byte("v1\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic v1 failed: %v", err)
	}
	if err := writeFileAtomic(p, []byte("v2\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic v2 failed: %v", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if string(b) != "v2\n" {
		t.Fatalf("unexpected content: %q", string(b))
	}
}

func TestValidateCoreStartInputs_RejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "mihomo")
	cfg := filepath.Join(tmp, "default.yaml")
	dataDir := filepath.Join(tmp, "data")
	logDir := filepath.Join(tmp, "logs")
	logPath := filepath.Join(logDir, "clashfox.log")

	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	if err := os.WriteFile(cfg, []byte("port: 7890\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}

	oldCfg := coreConfigPath
	oldData := coreDataDir
	oldLog := coreLogPath
	t.Cleanup(func() {
		coreConfigPath = oldCfg
		coreDataDir = oldData
		coreLogPath = oldLog
	})
	coreConfigPath = cfg
	coreDataDir = dataDir
	coreLogPath = logPath

	if err := validateCoreStartInputs(bin, cfg); err != nil {
		t.Fatalf("expected valid inputs, got %v", err)
	}

	symCfg := filepath.Join(tmp, "config-link.yaml")
	if err := os.Symlink(cfg, symCfg); err != nil {
		t.Fatalf("create symlink cfg: %v", err)
	}
	coreConfigPath = symCfg
	if err := validateCoreStartInputs(bin, symCfg); err == nil {
		t.Fatalf("expected symlink config to be rejected")
	}
}

func TestResolveCoreConfigPath(t *testing.T) {
	oldHome := coreUserHomeDir
	oldCfg := coreConfigPath
	t.Cleanup(func() {
		coreUserHomeDir = oldHome
		coreConfigPath = oldCfg
	})

	coreUserHomeDir = "/Users/alice"
	coreConfigPath = "/Users/alice/Library/Application Support/ClashFox/data/default.yaml"

	cfg, err := resolveCoreConfigPath("")
	if err != nil {
		t.Fatalf("empty config path should use default: %v", err)
	}
	if cfg != coreConfigPath {
		t.Fatalf("unexpected default config path: %q", cfg)
	}

	cfg, err = resolveCoreConfigPath("OneSmart.yaml")
	if err != nil {
		t.Fatalf("relative config file should be accepted: %v", err)
	}
	want := "/Users/alice/Library/Application Support/ClashFox/data/OneSmart.yaml"
	if cfg != want {
		t.Fatalf("unexpected resolved config path: got=%q want=%q", cfg, want)
	}

	cfg, err = resolveCoreConfigPath("/Users/alice/Library/Application Support/ClashFox/data/OnePro.yaml")
	if err != nil {
		t.Fatalf("absolute config file should be accepted: %v", err)
	}
	if cfg != "/Users/alice/Library/Application Support/ClashFox/data/OnePro.yaml" {
		t.Fatalf("unexpected absolute config path: %q", cfg)
	}

	if _, err := resolveCoreConfigPath("../escape.yaml"); err == nil {
		t.Fatalf("expected path traversal to be rejected")
	}
	if _, err := resolveCoreConfigPath("/tmp/other.yaml"); err == nil {
		t.Fatalf("expected out-of-base config path to be rejected")
	}
}

func TestCoreConfigPathFromArgs(t *testing.T) {
	if got := coreConfigPathFromArgs([]string{"-d", "/tmp/data", "-f", "/tmp/a.yaml"}); got != "/tmp/a.yaml" {
		t.Fatalf("unexpected config from args: %q", got)
	}
	if got := coreConfigPathFromArgs([]string{"-f", " /tmp/b.yaml "}); got != "/tmp/b.yaml" {
		t.Fatalf("unexpected trimmed config from args: %q", got)
	}
	if got := coreConfigPathFromArgs([]string{"-d", "/tmp/data"}); got != "" {
		t.Fatalf("expected empty config when -f missing, got %q", got)
	}
}

func TestStartupCheckEndpoint(t *testing.T) {
	h := newHandlerTestHelper()
	req := httptest.NewRequest(http.MethodGet, "/v1/startup/check", nil)
	req = withCaller(req)
	req.Header.Set("X-Helper-Token", "test-token")
	rr := httptest.NewRecorder()

	h.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}

	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			Paths         map[string]json.RawMessage `json:"paths"`
			PolicySummary map[string]json.RawMessage `json:"policySummary"`
			Runtime       map[string]json.RawMessage `json:"runtimeSummary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if len(resp.Data.Paths) == 0 {
		t.Fatalf("expected non-empty paths summary")
	}
	if _, ok := resp.Data.Paths["coreBinary"]; !ok {
		t.Fatalf("expected coreBinary path status")
	}
	if _, ok := resp.Data.PolicySummary["allowedUIDs"]; !ok {
		t.Fatalf("expected allowedUIDs in policy summary")
	}
	if _, ok := resp.Data.Runtime["routes"]; !ok {
		t.Fatalf("expected routes in runtime summary")
	}
}

func TestDisableProxy_NoOpAtBaselineClearsDesiredAndBaseline(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.state.Proxy = map[string]proxyDesired{
		"Wi-Fi": {
			Service: "Wi-Fi",
			Host:    "127.0.0.1",
			Enabled: true,
		},
	}
	h.baseline.Proxy = map[string]proxySnapshot{
		"Wi-Fi": {
			WebEnabled:           false,
			WebHost:              "",
			WebPort:              0,
			SecEnabled:           false,
			SecHost:              "",
			SecPort:              0,
			SocksEnabled:         false,
			SocksHost:            "",
			SocksPort:            0,
			AutoDiscoveryEnabled: false,
			AutoConfigEnabled:    false,
			AutoConfigURL:        "",
		},
	}
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return []byte("Enabled: No\nServer: \nPort: 0\n"), nil
		case "-getproxyautodiscovery":
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: \nEnabled: No\n"), nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/disable", strings.NewReader(`{"service":"Wi-Fi"}`))
	rr := httptest.NewRecorder()
	h.disableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool   `json:"ok"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK || resp.Code != "NOOP" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if _, ok := h.state.Proxy["Wi-Fi"]; ok {
		t.Fatalf("expected desired proxy state cleared after noop baseline disable")
	}
	if _, ok := h.baseline.Proxy["Wi-Fi"]; ok {
		t.Fatalf("expected baseline proxy cleared after noop baseline disable")
	}
}

func TestDisableProxy_NoBaselineAllDisabledConvergesStateToDisabled(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.state.Proxy = map[string]proxyDesired{
		"Wi-Fi": {
			Service: "Wi-Fi",
			Host:    "127.0.0.1",
			Enabled: true,
		},
	}
	h.baseline.Proxy = map[string]proxySnapshot{}
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return []byte("Enabled: No\nServer: \nPort: 0\n"), nil
		case "-getproxyautodiscovery":
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: \nEnabled: No\n"), nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/disable", strings.NewReader(`{"service":"Wi-Fi"}`))
	rr := httptest.NewRecorder()
	h.disableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool   `json:"ok"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK || resp.Code != "NOOP" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	got, ok := h.state.Proxy["Wi-Fi"]
	if !ok {
		t.Fatalf("expected proxy desired state retained as explicit disabled")
	}
	if got.Enabled {
		t.Fatalf("expected desired state converged to disabled, got %+v", got)
	}
}

func TestEnableProxy_WithStatusSnapshot(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()

	var webOn, secOn, socksOn bool
	var webHost, secHost, socksHost string
	var webPort, secPort, socksPort int
	proxyOut := func(enabled bool, host string, port int) []byte {
		enabledText := "No"
		if enabled {
			enabledText = "Yes"
		}
		return []byte("Enabled: " + enabledText + "\nServer: " + host + "\nPort: " + strconv.Itoa(port) + "\n")
	}
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-setwebproxy":
			webHost = args[2]
			webPort, _ = strconv.Atoi(args[3])
			return nil, nil
		case "-setwebproxystate":
			webOn = args[2] == "on"
			return nil, nil
		case "-setsecurewebproxy":
			secHost = args[2]
			secPort, _ = strconv.Atoi(args[3])
			return nil, nil
		case "-setsecurewebproxystate":
			secOn = args[2] == "on"
			return nil, nil
		case "-setsocksfirewallproxy":
			socksHost = args[2]
			socksPort, _ = strconv.Atoi(args[3])
			return nil, nil
		case "-setsocksfirewallproxystate":
			socksOn = args[2] == "on"
			return nil, nil
		case "-getwebproxy":
			return proxyOut(webOn, webHost, webPort), nil
		case "-getsecurewebproxy":
			return proxyOut(secOn, secHost, secPort), nil
		case "-getsocksfirewallproxy":
			return proxyOut(socksOn, socksHost, socksPort), nil
		case "-getproxyautodiscovery":
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: \nEnabled: No\n"), nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/enable?withStatus=1", strings.NewReader(`{"service":"Wi-Fi","host":"127.0.0.1","port":7890}`))
	rr := httptest.NewRecorder()
	h.enableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Data proxyStatusData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Data.Service != "Wi-Fi" {
		t.Fatalf("unexpected service: %q", resp.Data.Service)
	}
	if !resp.Data.AnyEnabled {
		t.Fatalf("expected anyEnabled=true")
	}
	if !resp.Data.HTTP.Enabled || resp.Data.HTTP.Server != "127.0.0.1" || resp.Data.HTTP.Port != 7890 {
		t.Fatalf("unexpected http status: %+v", resp.Data.HTTP)
	}
	if !resp.Data.HTTPS.Enabled || resp.Data.HTTPS.Server != "127.0.0.1" || resp.Data.HTTPS.Port != 7890 {
		t.Fatalf("unexpected https status: %+v", resp.Data.HTTPS)
	}
	if !resp.Data.SOCKS.Enabled || resp.Data.SOCKS.Server != "127.0.0.1" || resp.Data.SOCKS.Port != 7890 {
		t.Fatalf("unexpected socks status: %+v", resp.Data.SOCKS)
	}
}

func TestDisableProxy_WithStatusSnapshotOnNoop(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return []byte("Enabled: No\nServer: \nPort: 0\n"), nil
		case "-getproxyautodiscovery":
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: \nEnabled: No\n"), nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/disable?withStatus=1", strings.NewReader(`{"service":"Wi-Fi"}`))
	rr := httptest.NewRecorder()
	h.disableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool            `json:"ok"`
		Code string          `json:"code"`
		Data proxyStatusData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK || resp.Code != "NOOP" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Data.Service != "Wi-Fi" {
		t.Fatalf("unexpected service: %q", resp.Data.Service)
	}
	if resp.Data.AnyEnabled {
		t.Fatalf("expected anyEnabled=false")
	}
}

func TestEnableProxy_WithStatusSnapshotFailureStillSucceeds(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return []byte("Enabled: No\nServer: \nPort: 0\n"), nil
		case "-setwebproxy", "-setwebproxystate", "-setsecurewebproxy", "-setsecurewebproxystate", "-setsocksfirewallproxy", "-setsocksfirewallproxystate":
			return nil, nil
		case "-getproxyautodiscovery":
			return nil, os.ErrPermission
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/enable?withStatus=1", strings.NewReader(`{"service":"Wi-Fi","host":"127.0.0.1","port":7890}`))
	rr := httptest.NewRecorder()
	h.enableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool             `json:"ok"`
		Data *proxyStatusData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Data != nil {
		t.Fatalf("expected data omitted when status snapshot fails")
	}
	got, ok := h.state.Proxy["Wi-Fi"]
	if !ok || !got.Enabled || got.Host != "127.0.0.1" {
		t.Fatalf("expected desired proxy state applied, got=%+v ok=%v", got, ok)
	}
}

func TestDisableProxy_WithStatusSnapshotFailureStillSucceeds(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.state.Proxy = map[string]proxyDesired{
		"Wi-Fi": {
			Service: "Wi-Fi",
			Host:    "127.0.0.1",
			Enabled: true,
		},
	}

	var autoDiscoveryGets int
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy":
			return []byte("Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n"), nil
		case "-getproxyautodiscovery":
			autoDiscoveryGets++
			if autoDiscoveryGets >= 2 {
				return nil, os.ErrPermission
			}
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: \nEnabled: No\n"), nil
		case "-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate", "-setproxyautodiscovery", "-setautoproxystate":
			return nil, nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/proxy/disable?withStatus=1", strings.NewReader(`{"service":"Wi-Fi"}`))
	rr := httptest.NewRecorder()
	h.disableProxy(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool             `json:"ok"`
		Data *proxyStatusData `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Data != nil {
		t.Fatalf("expected data omitted when status snapshot fails")
	}
	got, ok := h.state.Proxy["Wi-Fi"]
	if !ok || got.Enabled {
		t.Fatalf("expected desired proxy state converged to disabled, got=%+v ok=%v", got, ok)
	}
}

func TestProxyStatusEndpoint(t *testing.T) {
	h := newHandlerTestHelper()
	h.servicesCache = map[string]struct{}{"Wi-Fi": {}}
	h.servicesAt = time.Now()
	h.commandRunner = func(kind string, args ...string) ([]byte, error) {
		switch args[0] {
		case "-getwebproxy":
			return []byte("Enabled: Yes\nServer: 127.0.0.1\nPort: 6152\n"), nil
		case "-getsecurewebproxy":
			return []byte("Enabled: Yes\nServer: 127.0.0.1\nPort: 6152\n"), nil
		case "-getsocksfirewallproxy":
			return []byte("Enabled: No\nServer: \nPort: 0\n"), nil
		case "-getproxyautodiscovery":
			return []byte("Auto Proxy Discovery: Off\n"), nil
		case "-getautoproxyurl":
			return []byte("URL: http://127.0.0.1:6152/proxy.pac\nEnabled: Yes\n"), nil
		default:
			t.Fatalf("unexpected command: kind=%s args=%v", kind, args)
			return nil, nil
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/proxy/status?service=Wi-Fi", nil)
	req = withCaller(req)
	req.Header.Set("X-Helper-Token", "test-token")
	rr := httptest.NewRecorder()
	h.routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			Service         string `json:"service"`
			AnyEnabled      bool   `json:"anyEnabled"`
			MatchesDesired  bool   `json:"matchesDesired"`
			ManagedByHelper bool   `json:"managedByHelper"`
			HTTP            struct {
				Enabled bool   `json:"enabled"`
				Server  string `json:"server"`
				Port    int    `json:"port"`
			} `json:"http"`
			HTTPS struct {
				Enabled bool   `json:"enabled"`
				Server  string `json:"server"`
				Port    int    `json:"port"`
			} `json:"https"`
			SOCKS struct {
				Enabled bool `json:"enabled"`
			} `json:"socks"`
			AutoDiscovery struct {
				Enabled bool `json:"enabled"`
			} `json:"autoDiscovery"`
			AutoConfig struct {
				Enabled bool   `json:"enabled"`
				URL     string `json:"url"`
			} `json:"autoConfig"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Data.Service != "Wi-Fi" {
		t.Fatalf("unexpected service: %q", resp.Data.Service)
	}
	if !resp.Data.AnyEnabled {
		t.Fatalf("expected anyEnabled=true")
	}
	if resp.Data.MatchesDesired {
		t.Fatalf("expected matchesDesired=false without desired state")
	}
	if resp.Data.ManagedByHelper {
		t.Fatalf("expected managedByHelper=false without desired state")
	}
	if !resp.Data.HTTP.Enabled || resp.Data.HTTP.Server != "127.0.0.1" || resp.Data.HTTP.Port != 6152 {
		t.Fatalf("unexpected http status: %+v", resp.Data.HTTP)
	}
	if !resp.Data.HTTPS.Enabled || resp.Data.HTTPS.Server != "127.0.0.1" || resp.Data.HTTPS.Port != 6152 {
		t.Fatalf("unexpected https status: %+v", resp.Data.HTTPS)
	}
	if resp.Data.SOCKS.Enabled {
		t.Fatalf("expected socks disabled")
	}
	if resp.Data.AutoDiscovery.Enabled {
		t.Fatalf("expected autoDiscovery disabled")
	}
	if !resp.Data.AutoConfig.Enabled || resp.Data.AutoConfig.URL != "http://127.0.0.1:6152/proxy.pac" {
		t.Fatalf("unexpected autoConfig status: %+v", resp.Data.AutoConfig)
	}
}
