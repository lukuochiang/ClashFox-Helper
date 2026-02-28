package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	socketPath            = "/var/run/com.clashfox.helper.sock"
	tokenPath             = "/Library/Application Support/ClashFox/helper/token"
	statePath             = "/Library/Application Support/ClashFox/helper/state.json"
	baselinePath          = "/Library/Application Support/ClashFox/helper/baseline.json"
	policyPath            = "/Library/Application Support/ClashFox/helper/policy.json"
	versionPath           = "/Library/Application Support/ClashFox/helper/version.json"
	corePIDPath           = "/Library/Application Support/ClashFox/helper/mihomo.pid"
	coreLockPath          = "/Library/Application Support/ClashFox/helper/mihomo.lock"
	coreLogPath           = "/var/log/clashfox-mihomo.log"
	coreManagedBinaryPath = "/Library/Application Support/ClashFox/core/mihomo"
	coreUpdateDir         = "/Library/Application Support/ClashFox/core/cfox-backup"
	coreBackupDir         = "/Library/Application Support/ClashFox/core/cfox-backup"
	coreConfigPath        = "/Library/Application Support/ClashFox/core/config.yaml"
	coreDataDir           = "/Library/Application Support/ClashFox/core"
	logPath               = "/var/log/clashfox-helper.log"
	auditPath             = "/var/log/clashfox-helper-audit.log"

	solLocal      = 0x0
	localPeerCred = 0x1
	localPeerPID  = 0x2
)

var (
	allowedCoreBinaries = []string{
		coreManagedBinaryPath,
		"/usr/local/bin/mihomo",
		"/opt/homebrew/bin/mihomo",
		"/Applications/ClashFox.app/Contents/Resources/mihomo",
	}
	coreArgsTemplate = []string{
		"-d", coreDataDir,
		"-f", coreConfigPath,
	}
)

var (
	reServiceName = regexp.MustCompile(`^[a-zA-Z0-9 _().-]{1,64}$`)
	appVersion    = "dev"
	gitCommit     = "none"
	buildTime     = "unknown"
)

type ctxKey string

const callerKey ctxKey = "caller"

type callerInfo struct {
	UID  uint32
	PID  int
	Path string
}

type helper struct {
	token string
	log   *log.Logger
	audit *log.Logger

	policyMu sync.RWMutex
	policy   policy

	stateMu sync.RWMutex
	state   desiredState

	baselineMu sync.RWMutex
	baseline   baselineState

	servicesMu    sync.RWMutex
	servicesCache map[string]struct{}
	servicesAt    time.Time

	serviceLocksMu sync.Mutex
	serviceLocks   map[string]*sync.Mutex
	tunMu          sync.Mutex

	rateMu   sync.Mutex
	rl       map[string]*rateBucket
	breaker  map[string]*breakerState
	rateConf rateConfig

	build buildInfo

	coreMu   sync.Mutex
	coreLock *os.File
}

type policy struct {
	AllowedUIDs                []uint32 `json:"allowedUIDs"`
	AllowedClientPathPrefixes  []string `json:"allowedClientPathPrefixes"`
	EnableCallerPathConstraint bool     `json:"enableCallerPathConstraint"`
}

type desiredState struct {
	Proxy *proxyDesired `json:"proxy,omitempty"`
	DNS   *dnsDesired   `json:"dns,omitempty"`
	TUN   *tunDesired   `json:"tun,omitempty"`
}

type baselineState struct {
	Proxy      map[string]proxySnapshot `json:"proxy,omitempty"`
	DNS        map[string][]string      `json:"dns,omitempty"`
	TUN        *tunDesired              `json:"tun,omitempty"`
	CapturedAt string                   `json:"capturedAt,omitempty"`
}

type proxyDesired struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
}

type dnsDesired struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

type tunDesired struct {
	IPForward bool `json:"ipForward"`
	PFEnabled bool `json:"pfEnabled"`
}

type jsonResp struct {
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type coreStatusResp struct {
	OK      bool      `json:"ok"`
	Running bool      `json:"running"`
	PID     int       `json:"pid,omitempty"`
	Binary  string    `json:"binary,omitempty"`
	Args    []string  `json:"args,omitempty"`
	Time    time.Time `json:"time"`
}

type corePIDRecord struct {
	PID       int    `json:"pid"`
	Binary    string `json:"binary"`
	StartedAt string `json:"startedAt"`
}

type buildInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"gitCommit"`
	BuildTime string `json:"buildTime"`
	Launched  string `json:"launchedAt"`
}

type rateConfig struct {
	Window           time.Duration
	MaxRequests      int
	BreakerWindow    time.Duration
	BreakerThreshold int
	BreakerTTL       time.Duration
}

type rateBucket struct {
	WindowStart time.Time
	Count       int
}

type breakerState struct {
	WindowStart time.Time
	Failures    int
	BlockedTill time.Time
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type setDNSReq struct {
	Service string   `json:"service"`
	Servers []string `json:"servers"`
}

type setProxyReq struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type tunReq struct {
	EnableIPForward bool `json:"enableIPForward"`
	EnablePF        bool `json:"enablePF"`
}

type proxySnapshot struct {
	WebEnabled bool
	WebHost    string
	WebPort    int
	SecEnabled bool
	SecHost    string
	SecPort    int
}

type xucred struct {
	Version uint32
	Uid     uint32
	Ngroups int16
	Groups  [16]uint32
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		info := buildInfo{
			Version:   appVersion,
			GitCommit: gitCommit,
			BuildTime: buildTime,
			Launched:  "",
		}
		b, _ := json.Marshal(info)
		fmt.Println(string(b))
		return
	}

	logger, closeLog, err := newFileLogger(logPath, "[clashfox-helper] ")
	if err != nil {
		log.Fatalf("open log: %v", err)
	}
	defer closeLog()

	audit, closeAudit, err := newFileLogger(auditPath, "")
	if err != nil {
		logger.Fatalf("open audit log: %v", err)
	}
	defer closeAudit()

	tok, err := ensureToken(tokenPath)
	if err != nil {
		logger.Fatalf("ensure token: %v", err)
	}

	pol, err := ensurePolicy(policyPath)
	if err != nil {
		logger.Fatalf("ensure policy: %v", err)
	}

	h := &helper{
		token:        strings.TrimSpace(tok),
		log:          logger,
		audit:        audit,
		policy:       pol,
		state:        loadStateBestEffort(statePath, logger),
		baseline:     loadBaselineBestEffort(baselinePath, logger),
		serviceLocks: map[string]*sync.Mutex{},
		rl:           map[string]*rateBucket{},
		breaker:      map[string]*breakerState{},
		build: buildInfo{
			Version:   appVersion,
			GitCommit: gitCommit,
			BuildTime: buildTime,
			Launched:  time.Now().Format(time.RFC3339),
		},
		rateConf: rateConfig{
			Window:           10 * time.Second,
			MaxRequests:      40,
			BreakerWindow:    60 * time.Second,
			BreakerThreshold: 8,
			BreakerTTL:       2 * time.Minute,
		},
	}
	h.saveVersionInfo()

	if err := os.RemoveAll(socketPath); err != nil {
		logger.Fatalf("remove stale socket: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	if err := os.Chmod(socketPath, 0o600); err != nil {
		logger.Fatalf("chmod socket: %v", err)
	}

	srv := &http.Server{
		Handler:      h.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ConnContext:  h.connContext,
	}

	go h.reconcileLoop()

	logger.Printf("helper started; socket=%s", socketPath)
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("serve: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	logger.Println("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = os.Remove(socketPath)
}

func newFileLogger(path, prefix string) (*log.Logger, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return log.New(f, prefix, log.LstdFlags|log.Lmicroseconds), f.Close, nil
}

func ensureToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)), nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func ensurePolicy(path string) (policy, error) {
	if b, err := os.ReadFile(path); err == nil {
		var p policy
		if err := json.Unmarshal(b, &p); err != nil {
			return policy{}, fmt.Errorf("parse policy: %w", err)
		}
		normalizePolicy(&p)
		return p, nil
	}

	uid := consoleUIDBestEffort()
	p := policy{
		AllowedUIDs:                []uint32{0, uid},
		AllowedClientPathPrefixes:  []string{"/Applications/ClashFox.app/", "/usr/local/bin/clashfox", "/usr/bin/curl"},
		EnableCallerPathConstraint: true,
	}
	normalizePolicy(&p)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return policy{}, err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return policy{}, err
	}
	return p, nil
}

func normalizePolicy(p *policy) {
	seenUID := make(map[uint32]struct{})
	var uids []uint32
	for _, uid := range p.AllowedUIDs {
		if _, ok := seenUID[uid]; ok {
			continue
		}
		seenUID[uid] = struct{}{}
		uids = append(uids, uid)
	}
	if len(uids) == 0 {
		uids = []uint32{0}
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	p.AllowedUIDs = uids

	var paths []string
	seenPath := make(map[string]struct{})
	for _, pref := range p.AllowedClientPathPrefixes {
		pref = strings.TrimSpace(pref)
		if pref == "" {
			continue
		}
		if _, ok := seenPath[pref]; ok {
			continue
		}
		seenPath[pref] = struct{}{}
		paths = append(paths, pref)
	}
	p.AllowedClientPathPrefixes = paths
}

func consoleUIDBestEffort() uint32 {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 501
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 501
	}
	return st.Uid
}

func loadStateBestEffort(path string, logger *log.Logger) desiredState {
	b, err := os.ReadFile(path)
	if err != nil {
		return desiredState{}
	}
	var s desiredState
	if err := json.Unmarshal(b, &s); err != nil {
		logger.Printf("ignore bad state file: %v", err)
		return desiredState{}
	}
	return s
}

func loadBaselineBestEffort(path string, logger *log.Logger) baselineState {
	b, err := os.ReadFile(path)
	if err != nil {
		return baselineState{}
	}
	var s baselineState
	if err := json.Unmarshal(b, &s); err != nil {
		logger.Printf("ignore bad baseline file: %v", err)
		return baselineState{}
	}
	return s
}

func (h *helper) saveState() {
	h.stateMu.RLock()
	stateCopy := h.state
	h.stateMu.RUnlock()

	b, _ := json.MarshalIndent(stateCopy, "", "  ")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		h.log.Printf("save state mkdir failed: %v", err)
		return
	}
	if err := os.WriteFile(statePath, append(b, '\n'), 0o600); err != nil {
		h.log.Printf("save state failed: %v", err)
	}
}

func (h *helper) saveBaseline() {
	h.baselineMu.RLock()
	baselineCopy := h.baseline
	h.baselineMu.RUnlock()

	b, _ := json.MarshalIndent(baselineCopy, "", "  ")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o700); err != nil {
		h.log.Printf("save baseline mkdir failed: %v", err)
		return
	}
	if err := os.WriteFile(baselinePath, append(b, '\n'), 0o600); err != nil {
		h.log.Printf("save baseline failed: %v", err)
	}
}

func (h *helper) saveVersionInfo() {
	b, _ := json.MarshalIndent(h.build, "", "  ")
	if err := os.MkdirAll(filepath.Dir(versionPath), 0o700); err != nil {
		h.log.Printf("save version mkdir failed: %v", err)
		return
	}
	if err := os.WriteFile(versionPath, append(b, '\n'), 0o600); err != nil {
		h.log.Printf("save version failed: %v", err)
	}
}

func (h *helper) withServiceLock(service string, fn func() error) error {
	h.serviceLocksMu.Lock()
	lk, ok := h.serviceLocks[service]
	if !ok {
		lk = &sync.Mutex{}
		h.serviceLocks[service] = lk
	}
	h.serviceLocksMu.Unlock()

	lk.Lock()
	defer lk.Unlock()
	return fn()
}

func (h *helper) withTunLock(fn func() error) error {
	h.tunMu.Lock()
	defer h.tunMu.Unlock()
	return fn()
}

func (h *helper) connContext(ctx context.Context, c net.Conn) context.Context {
	ci := callerInfo{}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return context.WithValue(ctx, callerKey, ci)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return context.WithValue(ctx, callerKey, ci)
	}
	_ = rc.Control(func(fd uintptr) {
		pid, err := syscall.GetsockoptInt(int(fd), solLocal, localPeerPID)
		if err == nil {
			ci.PID = pid
		}
		xucred, err := getsockoptXucred(int(fd), solLocal, localPeerCred)
		if err == nil {
			ci.UID = xucred.Uid
		}
	})
	if ci.PID > 0 {
		ci.Path = processPathBestEffort(ci.PID)
	}
	return context.WithValue(ctx, callerKey, ci)
}

func getsockoptXucred(fd int, level int, opt int) (*xucred, error) {
	var cred xucred
	size := uint32(unsafe.Sizeof(cred))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	return &cred, nil
}

func processPathBestEffort(pid int) string {
	lsof := exec.Command("/usr/sbin/lsof", "-a", "-p", strconv.Itoa(pid), "-d", "txt", "-Fn")
	if out, err := lsof.Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "n/") {
				return strings.TrimPrefix(strings.TrimSpace(line), "n")
			}
		}
	}

	ps := exec.Command("/bin/ps", "-p", strconv.Itoa(pid), "-o", "command=")
	out, err := ps.Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func (h *helper) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.withGuards("health", func(w http.ResponseWriter, _ *http.Request) {
		h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "alive"})
	}))
	mux.HandleFunc("/v1/proxy/global", h.withGuards("proxy_global", h.setGlobalProxy))
	mux.HandleFunc("/v1/proxy/off", h.withGuards("proxy_off", h.disableProxy))
	mux.HandleFunc("/v1/dns/set", h.withGuards("dns_set", h.setDNS))
	mux.HandleFunc("/v1/tun/enable", h.withGuards("tun_enable", h.enableTUNMode))
	mux.HandleFunc("/v1/tun/disable", h.withGuards("tun_disable", h.disableTUNMode))
	mux.HandleFunc("/v1/state/restore", h.withGuards("state_restore", h.restoreBaselineState))
	mux.HandleFunc("/v1/version", h.withGuards("version", h.versionInfo))
	mux.HandleFunc("/v1/core/start", h.withGuards("core_start", h.coreStart))
	mux.HandleFunc("/v1/core/stop", h.withGuards("core_stop", h.coreStop))
	mux.HandleFunc("/v1/core/restart", h.withGuards("core_restart", h.coreRestart))
	mux.HandleFunc("/v1/core/status", h.withGuards("core_status", h.coreStatus))
	mux.HandleFunc("/v1/core/reload", h.withGuards("core_reload", h.coreReload))
	mux.HandleFunc("/v1/core/config/validate", h.withGuards("core_config_validate", h.coreConfigValidate))
	mux.HandleFunc("/v1/core/switch", h.withGuards("core_switch", h.coreSwitch))
	return h.logRequests(mux)
}

func (h *helper) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ci := h.callerFromReq(r)
		h.log.Printf("%s %s caller_uid=%d caller_pid=%d caller_path=%q", r.Method, r.URL.Path, ci.UID, ci.PID, ci.Path)
		next.ServeHTTP(w, r)
	})
}

func (h *helper) withGuards(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ci := h.callerFromReq(r)
		callerKey := h.callerKey(ci)
		if blocked, remain := h.breakerBlocked(callerKey); blocked {
			h.auditf(action, ci, false, fmt.Sprintf("circuit open, retry after %s", remain.Truncate(time.Second)))
			h.writeErr(w, http.StatusTooManyRequests, "CIRCUIT_OPEN", "caller temporarily blocked due to repeated failures")
			return
		}
		if !h.allowRate(callerKey) {
			h.auditf(action, ci, false, "rate limit exceeded")
			h.writeErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests")
			return
		}
		if r.Header.Get("X-Helper-Token") != h.token {
			h.auditf(action, ci, false, "unauthorized token")
			h.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
			h.recordOutcome(callerKey, false)
			return
		}
		if !h.allowedCaller(ci) {
			h.auditf(action, ci, false, "blocked by caller policy")
			h.writeErr(w, http.StatusForbidden, "FORBIDDEN_CALLER", "forbidden caller")
			h.recordOutcome(callerKey, false)
			return
		}
		ww := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		next(ww, r)
		ok := ww.status < 400
		h.recordOutcome(callerKey, ok)
	}
}

func (h *helper) callerFromReq(r *http.Request) callerInfo {
	v := r.Context().Value(callerKey)
	ci, _ := v.(callerInfo)
	return ci
}

func (h *helper) callerKey(ci callerInfo) string {
	return fmt.Sprintf("%d:%d:%s", ci.UID, ci.PID, ci.Path)
}

func (h *helper) allowRate(key string) bool {
	now := time.Now()
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	b, ok := h.rl[key]
	if !ok || now.Sub(b.WindowStart) > h.rateConf.Window {
		h.rl[key] = &rateBucket{WindowStart: now, Count: 1}
		return true
	}
	if b.Count >= h.rateConf.MaxRequests {
		return false
	}
	b.Count++
	return true
}

func (h *helper) breakerBlocked(key string) (bool, time.Duration) {
	now := time.Now()
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	st, ok := h.breaker[key]
	if !ok {
		return false, 0
	}
	if now.Before(st.BlockedTill) {
		return true, st.BlockedTill.Sub(now)
	}
	return false, 0
}

func (h *helper) recordOutcome(key string, ok bool) {
	now := time.Now()
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	st, exists := h.breaker[key]
	if !exists || now.Sub(st.WindowStart) > h.rateConf.BreakerWindow {
		st = &breakerState{WindowStart: now}
		h.breaker[key] = st
	}
	if ok {
		if st.Failures > 0 {
			st.Failures--
		}
		return
	}
	st.Failures++
	if st.Failures >= h.rateConf.BreakerThreshold {
		st.BlockedTill = now.Add(h.rateConf.BreakerTTL)
		st.Failures = 0
		st.WindowStart = now
	}
}

func (h *helper) allowedCaller(ci callerInfo) bool {
	h.policyMu.RLock()
	p := h.policy
	h.policyMu.RUnlock()

	uidOK := false
	for _, uid := range p.AllowedUIDs {
		if uid == ci.UID {
			uidOK = true
			break
		}
	}
	if !uidOK {
		return false
	}
	if !p.EnableCallerPathConstraint {
		return true
	}
	if ci.Path == "" {
		return false
	}
	for _, pref := range p.AllowedClientPathPrefixes {
		if strings.HasPrefix(ci.Path, pref) {
			return true
		}
	}
	return false
}

func (h *helper) setGlobalProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	ci := h.callerFromReq(r)
	var req setProxyReq
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("proxy_global", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := h.validateService(req.Service); err != nil {
		h.auditf("proxy_global", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}
	if !validProxyHost(req.Host) || req.Port <= 0 || req.Port > 65535 {
		h.auditf("proxy_global", ci, false, "invalid proxy host/port")
		h.writeErr(w, http.StatusBadRequest, "INVALID_PROXY", "invalid proxy host/port")
		return
	}

	var opErr error
	var noop bool
	opErr = h.withServiceLock(req.Service, func() error {
		h.captureProxyBaselineIfNeeded(req.Service)
		curWebOn, curWebHost, curWebPort, err := h.getProxyConfig(req.Service, false)
		if err != nil {
			return err
		}
		curSecOn, curSecHost, curSecPort, err := h.getProxyConfig(req.Service, true)
		if err != nil {
			return err
		}
		if curWebOn && curSecOn && curWebHost == req.Host && curSecHost == req.Host && curWebPort == req.Port && curSecPort == req.Port {
			noop = true
			return nil
		}

		snap := proxySnapshot{
			WebEnabled: curWebOn,
			WebHost:    curWebHost,
			WebPort:    curWebPort,
			SecEnabled: curSecOn,
			SecHost:    curSecHost,
			SecPort:    curSecPort,
		}
		if err := h.applyProxy(req.Service, req.Host, req.Port, true); err != nil {
			_ = h.restoreProxy(req.Service, snap)
			return err
		}

		h.stateMu.Lock()
		h.state.Proxy = &proxyDesired{Service: req.Service, Host: req.Host, Port: req.Port, Enabled: true}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("proxy_global", ci, false, "apply failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("proxy_global", ci, true, "noop")
		h.writeNoop(w, "proxy already matches target")
		return
	}

	h.auditf("proxy_global", ci, true, fmt.Sprintf("service=%s host=%s port=%d", req.Service, req.Host, req.Port))
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true})
}

func (h *helper) disableProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	ci := h.callerFromReq(r)
	var req struct {
		Service string `json:"service"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("proxy_off", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := h.validateService(req.Service); err != nil {
		h.auditf("proxy_off", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}

	var opErr error
	var noop bool
	opErr = h.withServiceLock(req.Service, func() error {
		h.captureProxyBaselineIfNeeded(req.Service)
		curWebOn, curWebHost, curWebPort, err := h.getProxyConfig(req.Service, false)
		if err != nil {
			return err
		}
		curSecOn, curSecHost, curSecPort, err := h.getProxyConfig(req.Service, true)
		if err != nil {
			return err
		}
		if !curWebOn && !curSecOn {
			noop = true
			return nil
		}
		snap := proxySnapshot{
			WebEnabled: curWebOn,
			WebHost:    curWebHost,
			WebPort:    curWebPort,
			SecEnabled: curSecOn,
			SecHost:    curSecHost,
			SecPort:    curSecPort,
		}
		if err := h.applyProxy(req.Service, "", 0, false); err != nil {
			_ = h.restoreProxy(req.Service, snap)
			return err
		}

		h.stateMu.Lock()
		h.state.Proxy = &proxyDesired{Service: req.Service, Enabled: false}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("proxy_off", ci, false, "disable failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("proxy_off", ci, true, "noop")
		h.writeNoop(w, "proxy already disabled")
		return
	}

	h.auditf("proxy_off", ci, true, "service="+req.Service)
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true})
}

func (h *helper) setDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	ci := h.callerFromReq(r)
	var req setDNSReq
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("dns_set", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if err := h.validateService(req.Service); err != nil {
		h.auditf("dns_set", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}
	if len(req.Servers) == 0 || len(req.Servers) > 3 {
		h.auditf("dns_set", ci, false, "dns server count must be 1..3")
		h.writeErr(w, http.StatusBadRequest, "INVALID_DNS_COUNT", "dns server count must be 1..3")
		return
	}
	for _, s := range req.Servers {
		if ip := net.ParseIP(s); ip == nil {
			h.auditf("dns_set", ci, false, "invalid dns ip")
			h.writeErr(w, http.StatusBadRequest, "INVALID_DNS_IP", "invalid dns ip")
			return
		}
	}

	var opErr error
	var noop bool
	opErr = h.withServiceLock(req.Service, func() error {
		h.captureDNSBaselineIfNeeded(req.Service)
		before, err := h.getDNSServers(req.Service)
		if err != nil {
			return err
		}
		if sameStringSlice(before, req.Servers) {
			noop = true
			return nil
		}
		if err := h.setDNSServers(req.Service, req.Servers); err != nil {
			_ = h.setDNSServers(req.Service, before)
			return err
		}

		h.stateMu.Lock()
		h.state.DNS = &dnsDesired{Service: req.Service, Servers: append([]string(nil), req.Servers...)}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("dns_set", ci, false, "apply failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("dns_set", ci, true, "noop")
		h.writeNoop(w, "dns already matches target")
		return
	}

	h.auditf("dns_set", ci, true, fmt.Sprintf("service=%s servers=%v", req.Service, req.Servers))
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true})
}

func (h *helper) enableTUNMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	ci := h.callerFromReq(r)
	var req tunReq
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("tun_enable", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	var beforeForward bool
	var beforePF bool
	var opErr error
	var noop bool
	opErr = h.withTunLock(func() error {
		h.captureTUNBaselineIfNeeded()
		var err error
		beforeForward, err = h.getIPForwarding()
		if err != nil {
			return err
		}
		beforePF, err = h.getPFEnabled()
		if err != nil {
			return err
		}
		targetForward := req.EnableIPForward
		targetPF := req.EnablePF
		if beforeForward == targetForward && beforePF == targetPF {
			noop = true
			return nil
		}

		if targetForward != beforeForward {
			if err := h.setIPForwarding(targetForward); err != nil {
				return err
			}
		}
		if targetPF != beforePF {
			if err := h.setPF(targetPF); err != nil {
				_ = h.setIPForwarding(beforeForward)
				return err
			}
		}

		h.stateMu.Lock()
		h.state.TUN = &tunDesired{IPForward: targetForward, PFEnabled: targetPF}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("tun_enable", ci, false, "apply failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("tun_enable", ci, true, "noop")
		h.writeNoop(w, "tun already matches target")
		return
	}

	h.auditf("tun_enable", ci, true, fmt.Sprintf("ip_forward=%t pf=%t prev_ip_forward=%t prev_pf=%t", req.EnableIPForward, req.EnablePF, beforeForward, beforePF))
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "tun prerequisites enabled"})
}

func (h *helper) disableTUNMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	ci := h.callerFromReq(r)
	var opErr error
	var noop bool
	opErr = h.withTunLock(func() error {
		h.captureTUNBaselineIfNeeded()
		beforeForward, err := h.getIPForwarding()
		if err != nil {
			return err
		}
		beforePF, err := h.getPFEnabled()
		if err != nil {
			return err
		}
		if !beforeForward && !beforePF {
			noop = true
			return nil
		}

		if err := h.setIPForwarding(false); err != nil {
			return err
		}
		_ = h.setPF(false)

		h.stateMu.Lock()
		h.state.TUN = &tunDesired{IPForward: false, PFEnabled: false}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("tun_disable", ci, false, opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("tun_disable", ci, true, "noop")
		h.writeNoop(w, "tun already disabled")
		return
	}

	h.auditf("tun_disable", ci, true, "")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "tun prerequisites disabled"})
}

func (h *helper) restoreBaselineState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	ci := h.callerFromReq(r)
	var req struct {
		Service string `json:"service,omitempty"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			h.auditf("state_restore", ci, false, "invalid json")
			h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json")
			return
		}
	}

	h.baselineMu.RLock()
	b := h.baseline
	h.baselineMu.RUnlock()

	if req.Service != "" {
		if err := h.restoreServiceBaseline(req.Service, b); err != nil {
			h.auditf("state_restore", ci, false, err.Error())
			h.writeErr(w, http.StatusInternalServerError, "RESTORE_FAILED", err.Error())
			return
		}
		h.auditf("state_restore", ci, true, "service="+req.Service)
		h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "service baseline restored"})
		return
	}
	if err := h.restoreAllBaseline(b); err != nil {
		h.auditf("state_restore", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "RESTORE_FAILED", err.Error())
		return
	}
	h.auditf("state_restore", ci, true, "all")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "baseline restored"})
}

func (h *helper) versionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": h.build,
	})
}

func (h *helper) coreStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	running, pid, bin := coreRunningFromPIDFile()
	if bin == "" {
		bin, _ = selectCoreBinary()
	}
	h.writeJSON(w, http.StatusOK, coreStatusResp{
		OK:      true,
		Running: running,
		PID:     pid,
		Binary:  bin,
		Args:    append([]string(nil), coreArgsTemplate...),
		Time:    time.Now(),
	})
}

func (h *helper) coreStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	running, pid, _ := coreRunningFromPIDFile()
	if running {
		h.auditf("core_start", ci, true, fmt.Sprintf("noop pid=%d", pid))
		h.writeNoop(w, "core already running")
		return
	}
	if err := h.startCoreLocked(); err != nil {
		h.auditf("core_start", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_START_FAILED", err.Error())
		return
	}
	h.auditf("core_start", ci, true, "started")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "core started"})
}

func (h *helper) coreStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	running, pid, _ := coreRunningFromPIDFile()
	if !running {
		h.auditf("core_stop", ci, true, "noop")
		h.writeNoop(w, "core already stopped")
		return
	}
	if err := h.stopCoreLocked(pid); err != nil {
		h.auditf("core_stop", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_STOP_FAILED", err.Error())
		return
	}
	h.auditf("core_stop", ci, true, "stopped")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "core stopped"})
}

func (h *helper) coreRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	wasRunning, pid, oldBinary := coreRunningFromPIDFile()
	if wasRunning {
		if err := h.stopCoreLocked(pid); err != nil {
			h.auditf("core_restart", ci, false, "stop failed: "+err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_RESTART_FAILED", err.Error())
			return
		}
	}
	startErr := error(nil)
	if wasRunning && oldBinary != "" {
		startErr = h.startCoreWithBinaryLocked(oldBinary)
	} else {
		startErr = h.startCoreLocked()
	}
	if startErr != nil {
		h.auditf("core_restart", ci, false, "start failed: "+startErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_RESTART_FAILED", startErr.Error())
		return
	}
	h.auditf("core_restart", ci, true, "restarted")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "core restarted"})
}

func (h *helper) coreReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	running, pid, _ := coreRunningFromPIDFile()
	if !running {
		h.auditf("core_reload", ci, true, "noop")
		h.writeNoop(w, "core not running")
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		h.auditf("core_reload", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_RELOAD_FAILED", err.Error())
		return
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		h.auditf("core_reload", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_RELOAD_FAILED", err.Error())
		return
	}
	time.Sleep(250 * time.Millisecond)
	if !pidAlive(pid) {
		h.auditf("core_reload", ci, false, "core exited after reload signal")
		h.writeErr(w, http.StatusInternalServerError, "CORE_RELOAD_FAILED", "core exited after reload signal")
		return
	}
	h.auditf("core_reload", ci, true, fmt.Sprintf("pid=%d", pid))
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "reload signal sent"})
}

func (h *helper) coreConfigValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	bin := coreManagedBinaryPath
	if !isExecutableFile(bin) {
		var err error
		bin, err = selectCoreBinary()
		if err != nil {
			h.auditf("core_config_validate", ci, false, err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_VALIDATE_FAILED", err.Error())
			return
		}
	}
	args := append([]string(nil), coreArgsTemplate...)
	args = append(args, "-t")
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		h.auditf("core_config_validate", ci, false, msg)
		h.writeErr(w, http.StatusBadRequest, "CORE_CONFIG_INVALID", msg)
		return
	}
	h.auditf("core_config_validate", ci, true, "ok")
	h.writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "config valid",
		"output":  strings.TrimSpace(string(out)),
	})
}

func (h *helper) coreSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.coreMu.Lock()
	defer h.coreMu.Unlock()

	ci := h.callerFromReq(r)
	var req struct {
		Candidate string `json:"candidate"`
		SHA256    string `json:"sha256,omitempty"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("core_switch", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	if !validCoreCandidate(req.Candidate) {
		h.auditf("core_switch", ci, false, "invalid candidate")
		h.writeErr(w, http.StatusBadRequest, "INVALID_CANDIDATE", "invalid candidate")
		return
	}
	src := filepath.Join(coreUpdateDir, req.Candidate)
	if !isExecutableFile(src) {
		h.auditf("core_switch", ci, false, "candidate binary not executable")
		h.writeErr(w, http.StatusBadRequest, "INVALID_CANDIDATE", "candidate binary not executable")
		return
	}
	if err := verifyCoreCandidateSHA256(src, req.SHA256); err != nil {
		h.auditf("core_switch", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_CANDIDATE_HASH", err.Error())
		return
	}

	wasRunning, pid, _ := coreRunningFromPIDFile()
	if wasRunning {
		if err := h.stopCoreLocked(pid); err != nil {
			h.auditf("core_switch", ci, false, "stop failed: "+err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
			return
		}
	}

	if err := os.MkdirAll(filepath.Dir(coreManagedBinaryPath), 0o755); err != nil {
		h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
		return
	}
	if err := os.MkdirAll(coreBackupDir, 0o755); err != nil {
		h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
		return
	}

	backupPath := ""
	if isExecutableFile(coreManagedBinaryPath) {
		backupPath = filepath.Join(coreBackupDir, time.Now().Format("20060102-150405")+"-mihomo")
		if err := copyFile(coreManagedBinaryPath, backupPath, 0o755); err != nil {
			h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
			return
		}
	}

	tmpPath := coreManagedBinaryPath + ".new." + strconv.Itoa(os.Getpid())
	if err := copyFile(src, tmpPath, 0o755); err != nil {
		h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
		return
	}
	if err := os.Rename(tmpPath, coreManagedBinaryPath); err != nil {
		_ = os.Remove(tmpPath)
		h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
		return
	}

	if wasRunning {
		if err := h.startCoreWithBinaryLocked(coreManagedBinaryPath); err != nil {
			if backupPath != "" {
				_ = copyFile(backupPath, coreManagedBinaryPath, 0o755)
				if rbErr := h.startCoreWithBinaryLocked(coreManagedBinaryPath); rbErr != nil {
					h.auditf("core_switch", ci, false, "rollback restart failed: "+rbErr.Error())
					h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", "new core failed and rollback restart failed: "+rbErr.Error())
					return
				}
			}
			h.auditf("core_switch", ci, false, "new binary start failed, rolled back: "+err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
			return
		}
	} else {
		if err := h.validateCoreStartupLocked(coreManagedBinaryPath); err != nil {
			if backupPath != "" {
				_ = copyFile(backupPath, coreManagedBinaryPath, 0o755)
			}
			h.auditf("core_switch", ci, false, "new binary validation failed, rolled back: "+err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_SWITCH_FAILED", err.Error())
			return
		}
	}
	h.auditf("core_switch", ci, true, fmt.Sprintf("candidate=%s switched_to=%s", req.Candidate, coreManagedBinaryPath))
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "core switched"})
}

func (h *helper) startCoreLocked() error {
	bin, err := selectCoreBinary()
	if err != nil {
		return err
	}
	return h.startCoreWithBinaryLocked(bin)
}

func (h *helper) startCoreWithBinaryLocked(bin string) error {
	if !isAllowedCoreBinary(bin) {
		return errors.New("binary path not allowed")
	}
	if err := os.MkdirAll(filepath.Dir(corePIDPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(coreLogPath), 0o755); err != nil {
		return err
	}

	lockf, err := os.OpenFile(coreLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lockf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockf.Close()
		return errors.New("core lock is held")
	}

	logf, err := os.OpenFile(coreLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return err
	}
	cmd := exec.Command(bin, coreArgsTemplate...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return err
	}
	rec := corePIDRecord{
		PID:       cmd.Process.Pid,
		Binary:    bin,
		StartedAt: time.Now().Format(time.RFC3339),
	}
	pidBytes, _ := json.Marshal(rec)
	if err := os.WriteFile(corePIDPath, append(pidBytes, '\n'), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_ = logf.Close()
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return err
	}
	h.coreLock = lockf
	go h.watchCoreExit(cmd, logf, lockf)
	return nil
}

func (h *helper) stopCoreLocked(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = proc.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			_ = os.Remove(corePIDPath)
			h.releaseCoreLockLocked()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	_ = proc.Signal(syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
	_ = os.Remove(corePIDPath)
	h.releaseCoreLockLocked()
	return nil
}

func (h *helper) validateCoreStartupLocked(bin string) error {
	if err := h.startCoreWithBinaryLocked(bin); err != nil {
		return err
	}
	time.Sleep(400 * time.Millisecond)
	running, pid, _ := coreRunningFromPIDFile()
	if !running || pid <= 1 {
		return errors.New("core failed immediate startup validation")
	}
	return h.stopCoreLocked(pid)
}

func (h *helper) watchCoreExit(cmd *exec.Cmd, logf *os.File, lockf *os.File) {
	err := cmd.Wait()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	h.log.Printf("core exited pid=%d exit_code=%d err=%v", cmd.Process.Pid, exitCode, err)
	rec := map[string]any{
		"ts":       time.Now().Format(time.RFC3339Nano),
		"act":      "core_exit",
		"ok":       exitCode == 0,
		"pid":      cmd.Process.Pid,
		"exitCode": exitCode,
		"error":    fmt.Sprintf("%v", err),
	}
	if b, e := json.Marshal(rec); e == nil {
		h.audit.Println(string(b))
	}
	_ = logf.Close()
	_ = os.Remove(corePIDPath)

	h.coreMu.Lock()
	if h.coreLock == lockf {
		h.releaseCoreLockLocked()
	}
	h.coreMu.Unlock()
}

func (h *helper) releaseCoreLockLocked() {
	if h.coreLock == nil {
		return
	}
	_ = syscall.Flock(int(h.coreLock.Fd()), syscall.LOCK_UN)
	_ = h.coreLock.Close()
	h.coreLock = nil
}

func selectCoreBinary() (string, error) {
	for _, p := range allowedCoreBinaries {
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errors.New("mihomo binary not found in allowed paths")
}

func isAllowedCoreBinary(path string) bool {
	for _, p := range allowedCoreBinaries {
		if path == p {
			return true
		}
	}
	return false
}

func isAllowedCoreBinaryPath(path string) bool {
	if path == "" {
		return false
	}
	for _, p := range allowedCoreBinaries {
		a, err1 := filepath.EvalSymlinks(path)
		b, err2 := filepath.EvalSymlinks(p)
		if err1 == nil && err2 == nil && a == b {
			return true
		}
		if filepath.Clean(path) == filepath.Clean(p) {
			return true
		}
	}
	return false
}

func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return false
	}
	return st.Mode()&0o111 != 0
}

func validCoreCandidate(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return false
	}
	re := regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
	return re.MatchString(name)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode)
}

func coreRunningFromPIDFile() (bool, int, string) {
	rec, err := readCorePIDRecord()
	if err != nil || rec.PID <= 1 {
		return false, 0, ""
	}
	if !pidAlive(rec.PID) {
		return false, rec.PID, rec.Binary
	}
	if rec.Binary == "" {
		actual := processPathBestEffort(rec.PID)
		if !isAllowedCoreBinaryPath(actual) {
			return false, rec.PID, ""
		}
		return true, rec.PID, actual
	}
	if rec.Binary != "" && !pidMatchesBinary(rec.PID, rec.Binary) {
		return false, rec.PID, rec.Binary
	}
	return true, rec.PID, rec.Binary
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}

func readCorePIDRecord() (corePIDRecord, error) {
	b, err := os.ReadFile(corePIDPath)
	if err != nil {
		return corePIDRecord{}, err
	}
	txt := strings.TrimSpace(string(b))
	// Backward compatibility: old format is plain pid.
	if p, e := strconv.Atoi(txt); e == nil {
		return corePIDRecord{PID: p, Binary: "", StartedAt: ""}, nil
	}
	var rec corePIDRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return corePIDRecord{}, err
	}
	return rec, nil
}

func pidMatchesBinary(pid int, expected string) bool {
	actual := processPathBestEffort(pid)
	if actual == "" {
		return false
	}
	a, err1 := filepath.EvalSymlinks(actual)
	e, err2 := filepath.EvalSymlinks(expected)
	if err1 == nil && err2 == nil {
		return a == e
	}
	return filepath.Clean(actual) == filepath.Clean(expected)
}

func verifyCoreCandidateSHA256(path string, reqHash string) error {
	want := strings.TrimSpace(strings.ToLower(reqHash))
	if want == "" {
		shaPath := path + ".sha256"
		b, err := os.ReadFile(shaPath)
		if err != nil {
			return errors.New("sha256 is required (request sha256 or companion .sha256 file)")
		}
		fields := strings.Fields(strings.TrimSpace(string(b)))
		if len(fields) == 0 {
			return errors.New("empty sha256 file")
		}
		want = strings.ToLower(fields[0])
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(want) {
		return errors.New("invalid sha256 format")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 mismatch: got=%s", got)
	}
	return nil
}

func (h *helper) restoreServiceBaseline(service string, b baselineState) error {
	found := false
	if snap, ok := b.Proxy[service]; ok {
		found = true
		if err := h.withServiceLock(service, func() error { return h.restoreProxy(service, snap) }); err != nil {
			return err
		}
		h.stateMu.Lock()
		if snap.WebEnabled && snap.SecEnabled && snap.WebHost != "" && snap.WebPort > 0 {
			h.state.Proxy = &proxyDesired{
				Service: service,
				Host:    snap.WebHost,
				Port:    snap.WebPort,
				Enabled: true,
			}
		} else {
			h.state.Proxy = &proxyDesired{Service: service, Enabled: false}
		}
		h.stateMu.Unlock()
	}
	if dns, ok := b.DNS[service]; ok {
		found = true
		if err := h.withServiceLock(service, func() error { return h.setDNSServers(service, dns) }); err != nil {
			return err
		}
		h.stateMu.Lock()
		h.state.DNS = &dnsDesired{Service: service, Servers: append([]string(nil), dns...)}
		h.stateMu.Unlock()
	}
	if !found {
		return fmt.Errorf("no baseline for service: %s", service)
	}
	h.saveState()
	return nil
}

func (h *helper) restoreAllBaseline(b baselineState) error {
	for service, snap := range b.Proxy {
		svc := service
		ps := snap
		if err := h.withServiceLock(svc, func() error { return h.restoreProxy(svc, ps) }); err != nil {
			return err
		}
		h.stateMu.Lock()
		if ps.WebEnabled && ps.SecEnabled && ps.WebHost != "" && ps.WebPort > 0 {
			h.state.Proxy = &proxyDesired{Service: svc, Host: ps.WebHost, Port: ps.WebPort, Enabled: true}
		} else {
			h.state.Proxy = &proxyDesired{Service: svc, Enabled: false}
		}
		h.stateMu.Unlock()
	}
	for service, dns := range b.DNS {
		svc := service
		d := append([]string(nil), dns...)
		if err := h.withServiceLock(svc, func() error { return h.setDNSServers(svc, d) }); err != nil {
			return err
		}
		h.stateMu.Lock()
		h.state.DNS = &dnsDesired{Service: svc, Servers: append([]string(nil), d...)}
		h.stateMu.Unlock()
	}
	if b.TUN != nil {
		bt := *b.TUN
		if err := h.withTunLock(func() error {
			if err := h.setIPForwarding(bt.IPForward); err != nil {
				return err
			}
			if err := h.setPF(bt.PFEnabled); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return err
		}
		h.stateMu.Lock()
		h.state.TUN = &tunDesired{IPForward: bt.IPForward, PFEnabled: bt.PFEnabled}
		h.stateMu.Unlock()
	}
	h.saveState()
	return nil
}

func (h *helper) validateService(service string) error {
	if !reServiceName.MatchString(service) {
		return errors.New("invalid service name")
	}
	services, err := h.availableServices()
	if err != nil {
		return err
	}
	if _, ok := services[service]; !ok {
		return fmt.Errorf("service not found: %s", service)
	}
	return nil
}

func (h *helper) availableServices() (map[string]struct{}, error) {
	h.servicesMu.RLock()
	if time.Since(h.servicesAt) < 60*time.Second && len(h.servicesCache) > 0 {
		copyMap := make(map[string]struct{}, len(h.servicesCache))
		for k, v := range h.servicesCache {
			copyMap[k] = v
		}
		h.servicesMu.RUnlock()
		return copyMap, nil
	}
	h.servicesMu.RUnlock()

	out, err := h.runAllowed(cmdNetworkSetup, "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	services := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		if line != "" {
			services[line] = struct{}{}
		}
	}
	if len(services) == 0 {
		return nil, errors.New("no network services found")
	}

	h.servicesMu.Lock()
	h.servicesCache = services
	h.servicesAt = time.Now()
	h.servicesMu.Unlock()

	copyMap := make(map[string]struct{}, len(services))
	for k, v := range services {
		copyMap[k] = v
	}
	return copyMap, nil
}

func validProxyHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func (h *helper) readProxySnapshot(service string) (proxySnapshot, error) {
	webEnabled, webHost, webPort, err := h.getProxyConfig(service, false)
	if err != nil {
		return proxySnapshot{}, err
	}
	secEnabled, secHost, secPort, err := h.getProxyConfig(service, true)
	if err != nil {
		return proxySnapshot{}, err
	}
	return proxySnapshot{
		WebEnabled: webEnabled,
		WebHost:    webHost,
		WebPort:    webPort,
		SecEnabled: secEnabled,
		SecHost:    secHost,
		SecPort:    secPort,
	}, nil
}

func (h *helper) restoreProxy(service string, s proxySnapshot) error {
	if s.WebEnabled {
		if err := h.setOneProxy(service, false, s.WebHost, s.WebPort, true); err != nil {
			return err
		}
	} else {
		if err := h.setOneProxy(service, false, "", 0, false); err != nil {
			return err
		}
	}
	if s.SecEnabled {
		if err := h.setOneProxy(service, true, s.SecHost, s.SecPort, true); err != nil {
			return err
		}
	} else {
		if err := h.setOneProxy(service, true, "", 0, false); err != nil {
			return err
		}
	}
	return nil
}

func (h *helper) applyProxy(service, host string, port int, enable bool) error {
	if err := h.setOneProxy(service, false, host, port, enable); err != nil {
		return err
	}
	if err := h.setOneProxy(service, true, host, port, enable); err != nil {
		return err
	}
	return nil
}

func (h *helper) setOneProxy(service string, secure bool, host string, port int, enable bool) error {
	if secure {
		if enable {
			if _, err := h.runAllowed(cmdNetworkSetup, "-setsecurewebproxy", service, host, strconv.Itoa(port)); err != nil {
				return err
			}
			_, err := h.runAllowed(cmdNetworkSetup, "-setsecurewebproxystate", service, "on")
			return err
		}
		_, err := h.runAllowed(cmdNetworkSetup, "-setsecurewebproxystate", service, "off")
		return err
	}

	if enable {
		if _, err := h.runAllowed(cmdNetworkSetup, "-setwebproxy", service, host, strconv.Itoa(port)); err != nil {
			return err
		}
		_, err := h.runAllowed(cmdNetworkSetup, "-setwebproxystate", service, "on")
		return err
	}
	_, err := h.runAllowed(cmdNetworkSetup, "-setwebproxystate", service, "off")
	return err
}

func (h *helper) getProxyConfig(service string, secure bool) (enabled bool, host string, port int, err error) {
	var out []byte
	if secure {
		out, err = h.runAllowed(cmdNetworkSetup, "-getsecurewebproxy", service)
	} else {
		out, err = h.runAllowed(cmdNetworkSetup, "-getwebproxy", service)
	}
	if err != nil {
		return false, "", 0, err
	}
	return parseProxyConfigOutput(out)
}

func (h *helper) getDNSServers(service string) ([]string, error) {
	out, err := h.runAllowed(cmdNetworkSetup, "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	txt := strings.TrimSpace(string(out))
	if txt == "" || strings.Contains(txt, "There aren't any DNS Servers set on") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(txt, "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil {
			servers = append(servers, line)
		}
	}
	return servers, nil
}

func (h *helper) setDNSServers(service string, servers []string) error {
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		args = append(args, "empty")
	} else {
		args = append(args, servers...)
	}
	_, err := h.runAllowed(cmdNetworkSetup, args...)
	return err
}

func (h *helper) setIPForwarding(enable bool) error {
	v := "0"
	if enable {
		v = "1"
	}
	_, err := h.runAllowed(cmdSysctl, "-w", "net.inet.ip.forwarding="+v)
	return err
}

func (h *helper) getIPForwarding() (bool, error) {
	out, err := h.runAllowed(cmdSysctl, "-n", "net.inet.ip.forwarding")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "1", nil
}

func (h *helper) setPF(enable bool) error {
	if enable {
		_, err := h.runAllowed(cmdPFCTL, "-E")
		return err
	}
	_, err := h.runAllowed(cmdPFCTL, "-d")
	return err
}

func (h *helper) getPFEnabled() (bool, error) {
	out, err := h.runAllowed(cmdPFCTL, "-s", "info")
	if err != nil {
		return false, err
	}
	return parsePFStatusOutput(out)
}

func parseProxyConfigOutput(out []byte) (enabled bool, host string, port int, err error) {
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "Enabled":
			enabled = strings.EqualFold(v, "Yes")
		case "Server":
			host = v
		case "Port":
			if p, e := strconv.Atoi(v); e == nil {
				port = p
			}
		}
	}
	if host == "" && port == 0 && !enabled {
		// networksetup off-state may still be valid. keep permissive.
	}
	return enabled, host, port, nil
}

func parsePFStatusOutput(out []byte) (bool, error) {
	txt := string(out)
	if strings.Contains(txt, "Status: Enabled") {
		return true, nil
	}
	if strings.Contains(txt, "Status: Disabled") {
		return false, nil
	}
	return false, errors.New("unexpected pf status")
}

const (
	cmdNetworkSetup = "networksetup"
	cmdSysctl       = "sysctl"
	cmdPFCTL        = "pfctl"
)

func (h *helper) runAllowed(kind string, args ...string) ([]byte, error) {
	bin, err := allowedCommand(kind, args)
	if err != nil {
		return nil, err
	}
	c := exec.Command(bin, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		h.log.Printf("command failed: %s %s => %v, out=%s", bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		return nil, fmt.Errorf("command failed: %s", strings.TrimSpace(string(out)))
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed != "" {
		h.log.Printf("command output: %s", trimmed)
	}
	return out, nil
}

func allowedCommand(kind string, args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("empty command args")
	}
	sub := args[0]
	switch kind {
	case cmdNetworkSetup:
		allowed := map[string]struct{}{
			"-listallnetworkservices": {},
			"-setwebproxy":            {},
			"-setsecurewebproxy":      {},
			"-setwebproxystate":       {},
			"-setsecurewebproxystate": {},
			"-getwebproxy":            {},
			"-getsecurewebproxy":      {},
			"-setdnsservers":          {},
			"-getdnsservers":          {},
		}
		if _, ok := allowed[sub]; !ok {
			return "", fmt.Errorf("networksetup subcommand not allowed: %s", sub)
		}
		return "/usr/sbin/networksetup", nil
	case cmdSysctl:
		joined := strings.Join(args, " ")
		if joined != "-w net.inet.ip.forwarding=0" && joined != "-w net.inet.ip.forwarding=1" && joined != "-n net.inet.ip.forwarding" {
			return "", errors.New("sysctl args not allowed")
		}
		return "/usr/sbin/sysctl", nil
	case cmdPFCTL:
		joined := strings.Join(args, " ")
		if joined != "-E" && joined != "-d" && joined != "-s info" {
			return "", errors.New("pfctl args not allowed")
		}
		return "/sbin/pfctl", nil
	default:
		return "", fmt.Errorf("command kind not allowed: %s", kind)
	}
}

func decodeJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func (h *helper) writeErr(w http.ResponseWriter, status int, code, msg string) {
	h.writeJSON(w, status, jsonResp{OK: false, Code: code, Message: msg})
}

func (h *helper) writeNoop(w http.ResponseWriter, msg string) {
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Code: "NOOP", Message: msg})
}

func (h *helper) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *helper) captureProxyBaselineIfNeeded(service string) {
	h.baselineMu.RLock()
	_, exists := h.baseline.Proxy[service]
	h.baselineMu.RUnlock()
	if exists {
		return
	}
	snap, err := h.readProxySnapshot(service)
	if err != nil {
		h.log.Printf("capture proxy baseline failed: %v", err)
		return
	}
	h.baselineMu.Lock()
	if h.baseline.Proxy == nil {
		h.baseline.Proxy = map[string]proxySnapshot{}
	}
	if _, ok := h.baseline.Proxy[service]; !ok {
		h.baseline.Proxy[service] = snap
		if h.baseline.CapturedAt == "" {
			h.baseline.CapturedAt = time.Now().Format(time.RFC3339)
		}
	}
	h.baselineMu.Unlock()
	h.saveBaseline()
}

func (h *helper) captureDNSBaselineIfNeeded(service string) {
	h.baselineMu.RLock()
	_, exists := h.baseline.DNS[service]
	h.baselineMu.RUnlock()
	if exists {
		return
	}
	dns, err := h.getDNSServers(service)
	if err != nil {
		h.log.Printf("capture dns baseline failed: %v", err)
		return
	}
	h.baselineMu.Lock()
	if h.baseline.DNS == nil {
		h.baseline.DNS = map[string][]string{}
	}
	if _, ok := h.baseline.DNS[service]; !ok {
		h.baseline.DNS[service] = append([]string(nil), dns...)
		if h.baseline.CapturedAt == "" {
			h.baseline.CapturedAt = time.Now().Format(time.RFC3339)
		}
	}
	h.baselineMu.Unlock()
	h.saveBaseline()
}

func (h *helper) captureTUNBaselineIfNeeded() {
	h.baselineMu.RLock()
	exists := h.baseline.TUN != nil
	h.baselineMu.RUnlock()
	if exists {
		return
	}
	ipForward, err1 := h.getIPForwarding()
	pfEnabled, err2 := h.getPFEnabled()
	if err1 != nil || err2 != nil {
		h.log.Printf("capture tun baseline failed: ip_err=%v pf_err=%v", err1, err2)
		return
	}
	h.baselineMu.Lock()
	if h.baseline.TUN == nil {
		h.baseline.TUN = &tunDesired{IPForward: ipForward, PFEnabled: pfEnabled}
		if h.baseline.CapturedAt == "" {
			h.baseline.CapturedAt = time.Now().Format(time.RFC3339)
		}
	}
	h.baselineMu.Unlock()
	h.saveBaseline()
}

func (h *helper) auditf(action string, ci callerInfo, ok bool, msg string) {
	rec := map[string]any{
		"ts":    time.Now().Format(time.RFC3339Nano),
		"act":   action,
		"ok":    ok,
		"uid":   ci.UID,
		"pid":   ci.PID,
		"path":  ci.Path,
		"msg":   msg,
		"state": h.stateSummary(),
	}
	b, _ := json.Marshal(rec)
	h.audit.Println(string(b))
}

func (h *helper) driftf(kind, service, expected, current string) {
	rec := map[string]any{
		"ts":       time.Now().Format(time.RFC3339Nano),
		"act":      "drift_detected",
		"ok":       true,
		"kind":     kind,
		"service":  service,
		"expected": expected,
		"current":  current,
	}
	b, _ := json.Marshal(rec)
	h.audit.Println(string(b))
}

func (h *helper) stateSummary() string {
	h.stateMu.RLock()
	defer h.stateMu.RUnlock()
	b, _ := json.Marshal(h.state)
	return string(b)
}

func (h *helper) reconcileLoop() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.reconcileOnce()
	}
}

func (h *helper) reconcileOnce() {
	h.stateMu.RLock()
	s := h.state
	h.stateMu.RUnlock()

	if s.Proxy != nil {
		_ = h.withServiceLock(s.Proxy.Service, func() error {
			enabledWeb, webHost, webPort, err1 := h.getProxyConfig(s.Proxy.Service, false)
			enabledSec, secHost, secPort, err2 := h.getProxyConfig(s.Proxy.Service, true)
			if err1 != nil || err2 != nil {
				return nil
			}
			if s.Proxy.Enabled {
				if !enabledWeb || !enabledSec || webHost != s.Proxy.Host || secHost != s.Proxy.Host || webPort != s.Proxy.Port || secPort != s.Proxy.Port {
					h.driftf(
						"proxy",
						s.Proxy.Service,
						fmt.Sprintf("enabled=true host=%s port=%d", s.Proxy.Host, s.Proxy.Port),
						fmt.Sprintf("web_enabled=%t web_host=%s web_port=%d sec_enabled=%t sec_host=%s sec_port=%d", enabledWeb, webHost, webPort, enabledSec, secHost, secPort),
					)
					if err := h.applyProxy(s.Proxy.Service, s.Proxy.Host, s.Proxy.Port, true); err != nil {
						h.log.Printf("self-heal proxy apply failed: %v", err)
					} else {
						h.log.Printf("self-heal proxy reapplied for service=%s", s.Proxy.Service)
					}
				}
			} else {
				if enabledWeb || enabledSec {
					h.driftf(
						"proxy",
						s.Proxy.Service,
						"enabled=false",
						fmt.Sprintf("web_enabled=%t sec_enabled=%t", enabledWeb, enabledSec),
					)
					if err := h.applyProxy(s.Proxy.Service, "", 0, false); err != nil {
						h.log.Printf("self-heal proxy disable failed: %v", err)
					} else {
						h.log.Printf("self-heal proxy disabled for service=%s", s.Proxy.Service)
					}
				}
			}
			return nil
		})
	}

	if s.DNS != nil {
		_ = h.withServiceLock(s.DNS.Service, func() error {
			cur, err := h.getDNSServers(s.DNS.Service)
			if err == nil && !sameStringSlice(cur, s.DNS.Servers) {
				h.driftf("dns", s.DNS.Service, strings.Join(s.DNS.Servers, ","), strings.Join(cur, ","))
				if err := h.setDNSServers(s.DNS.Service, s.DNS.Servers); err != nil {
					h.log.Printf("self-heal dns failed: %v", err)
				} else {
					h.log.Printf("self-heal dns reapplied for service=%s", s.DNS.Service)
				}
			}
			return nil
		})
	}

	if s.TUN != nil {
		_ = h.withTunLock(func() error {
			if got, err := h.getIPForwarding(); err == nil && got != s.TUN.IPForward {
				h.driftf("tun_ip_forward", "", strconv.FormatBool(s.TUN.IPForward), strconv.FormatBool(got))
				_ = h.setIPForwarding(s.TUN.IPForward)
			}
			if got, err := h.getPFEnabled(); err == nil && got != s.TUN.PFEnabled {
				h.driftf("tun_pf", "", strconv.FormatBool(s.TUN.PFEnabled), strconv.FormatBool(got))
				_ = h.setPF(s.TUN.PFEnabled)
			}
			return nil
		})
	}
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := append([]string(nil), a...)
	bCopy := append([]string(nil), b...)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	return bytes.Equal([]byte(strings.Join(aCopy, ",")), []byte(strings.Join(bCopy, ",")))
}
