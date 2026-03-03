package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"os/user"
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
	solLocal      = 0x0
	localPeerCred = 0x1
	localPeerPID  = 0x2
)

var (
	clashfoxSystemBase = "/Library/Application Support/ClashFox"
	helperStateDir     = filepath.Join(clashfoxSystemBase, "helper")

	tokenPath    = filepath.Join(helperStateDir, "token")
	statePath    = filepath.Join(helperStateDir, "state.json")
	baselinePath = filepath.Join(helperStateDir, "baseline.json")
	policyPath   = filepath.Join(helperStateDir, "policy.json")
	versionPath  = filepath.Join(helperStateDir, "version.json")
	corePIDPath  = filepath.Join(helperStateDir, "mihomo.pid")
	coreLockPath = filepath.Join(helperStateDir, "mihomo.lock")

	coreDataDir           = ""
	coreManagedBinaryPath = ""
	coreConfigPath        = ""
	coreLogPath           = ""
	coreUserHomeDir       = ""

	socketPath = "/var/run/com.clashfox.helper.sock"
	logPath    = "/var/log/clashfox-helper.log"
	auditPath  = "/var/log/clashfox-helper-audit.log"
)

var (
	allowedCoreBinaries = []string{
		coreManagedBinaryPath,
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

	rateMu   sync.Mutex
	rl       map[string]*rateBucket
	breaker  map[string]*breakerState
	rateConf rateConfig

	build buildInfo

	coreMu   sync.Mutex
	coreLock *os.File

	commandRunner func(kind string, args ...string) ([]byte, error)
}

type policy struct {
	AllowedUIDs                []uint32 `json:"allowedUIDs"`
	AllowedClientPathPrefixes  []string `json:"allowedClientPathPrefixes"`
	EnableCallerPathConstraint bool     `json:"enableCallerPathConstraint"`
}

type desiredState struct {
	Proxy map[string]proxyDesired `json:"proxy,omitempty"`
	DNS   map[string]dnsDesired   `json:"dns,omitempty"`
	TUN   *tunDesired             `json:"tun,omitempty"`
}

type legacyDesiredState struct {
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
	Service   string `json:"service"`
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"` // backward-compatible alias of httpPort
	HTTPPort  int    `json:"httpPort,omitempty"`
	HTTPSPort int    `json:"httpsPort,omitempty"`
	SOCKSPort int    `json:"socksPort,omitempty"`
	Enabled   bool   `json:"enabled"`
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
	Data    any    `json:"data,omitempty"`
}

type coreStatusData struct {
	Running bool      `json:"running"`
	PID     int       `json:"pid,omitempty"`
	Binary  string    `json:"binary,omitempty"`
	Args    []string  `json:"args,omitempty"`
	Time    time.Time `json:"time"`
}

type startupPathStatus struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Mode     string `json:"mode,omitempty"`
	Owner    string `json:"owner,omitempty"`
	IsDir    bool   `json:"isDir,omitempty"`
	IsSocket bool   `json:"isSocket,omitempty"`
	ACL      string `json:"acl,omitempty"`
	Error    string `json:"error,omitempty"`
}

type corePIDRecord struct {
	PID       int      `json:"pid"`
	Binary    string   `json:"binary"`
	StartedAt string   `json:"startedAt"`
	Args      []string `json:"args,omitempty"`
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

type setProxyReq struct {
	Service        string `json:"service"`
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	HTTPPort       int    `json:"httpPort,omitempty"`
	HTTPSPort      int    `json:"httpsPort,omitempty"`
	SOCKSPort      int    `json:"socksPort,omitempty"`
	MixedPort      int    `json:"mixedPort,omitempty"`
	HTTPPortKebab  int    `json:"http-port,omitempty"`
	HTTPSPortKebab int    `json:"https-port,omitempty"`
	SOCKSPortKebab int    `json:"socks-port,omitempty"`
	MixedPortKebab int    `json:"mixed-port,omitempty"`
}

type serviceOrderEntry struct {
	Service string
	Device  string
}

type proxySnapshot struct {
	WebEnabled   bool
	WebHost      string
	WebPort      int
	SecEnabled   bool
	SecHost      string
	SecPort      int
	SocksEnabled bool
	SocksHost    string
	SocksPort    int
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

	if err := refreshCoreRuntimePaths(); err != nil {
		logger.Fatalf("resolve core runtime paths: %v", err)
	}
	if err := validateCoreRuntimePaths(); err != nil {
		logger.Fatalf("invalid core runtime path policy: %v", err)
	}

	tok, err := ensureToken(tokenPath)
	if err != nil {
		logger.Fatalf("ensure token: %v", err)
	}

	pol, err := ensurePolicy(policyPath)
	if err != nil {
		logger.Fatalf("ensure policy: %v", err)
	}

	loadedState := trimStateForMinimalScope(loadStateBestEffort(statePath, logger))
	loadedBaseline := trimBaselineForMinimalScope(loadBaselineBestEffort(baselinePath, logger))

	h := &helper{
		token:        strings.TrimSpace(tok),
		log:          logger,
		audit:        audit,
		policy:       pol,
		state:        loadedState,
		baseline:     loadedBaseline,
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
	if err := h.enforceTokenPermissions(); err != nil {
		logger.Fatalf("secure token permission failed: %v", err)
	}

	if err := prepareSocketPath(socketPath); err != nil {
		logger.Fatalf("prepare socket path: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Fatalf("listen unix socket: %v", err)
	}
	defer ln.Close()

	if err := h.enforceSocketPermissions(socketPath); err != nil {
		logger.Fatalf("secure socket permission failed: %v", err)
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
		t := strings.TrimSpace(string(b))
		if t != "" {
			return t, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	if err := writeFileAtomic(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tmp := path + ".new." + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
		AllowedClientPathPrefixes:  []string{"/Applications/ClashFox.app/", "/usr/local/bin/clashfox"},
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

func refreshCoreRuntimePaths() error {
	uid := consoleUIDBestEffort()
	home := consoleHomeDirBestEffort(uid)
	dataDir, binPath, confPath, logPath, err := deriveCoreRuntimePaths(home)
	if err != nil {
		return err
	}
	coreDataDir = dataDir
	coreManagedBinaryPath = binPath
	coreConfigPath = confPath
	coreLogPath = logPath
	coreUserHomeDir = home
	allowedCoreBinaries = []string{
		coreManagedBinaryPath,
		"/Applications/ClashFox.app/Contents/Resources/mihomo",
	}
	coreArgsTemplate = []string{
		"-d", coreDataDir,
		"-f", coreConfigPath,
	}
	return nil
}

func deriveCoreRuntimePaths(home string) (string, string, string, string, error) {
	home = filepath.Clean(strings.TrimSpace(home))
	if home == "" || home == "." || home == "/" {
		return "", "", "", "", errors.New("no active user home resolved for core runtime")
	}
	if !strings.HasPrefix(home, "/Users/") {
		return "", "", "", "", fmt.Errorf("invalid home for core runtime: %s", home)
	}
	base := filepath.Join(home, "Library", "Application Support", "ClashFox")
	dataDir := filepath.Join(base, "data")
	binPath := filepath.Join(base, "core", "mihomo")
	confPath := filepath.Join(base, "config", "config.yaml")
	logPath := filepath.Join(base, "logs", "clashfox.log")
	return dataDir, binPath, confPath, logPath, nil
}

func validateCoreRuntimePaths() error {
	home := filepath.Clean(strings.TrimSpace(coreUserHomeDir))
	if home == "" || !strings.HasPrefix(home, "/Users/") {
		return errors.New("missing user home for core runtime")
	}
	base := filepath.Join(home, "Library", "Application Support", "ClashFox")
	if !pathWithinBase(coreDataDir, base) {
		return fmt.Errorf("core data dir out of base: %s", coreDataDir)
	}
	if !pathWithinBase(coreManagedBinaryPath, base) {
		return fmt.Errorf("core binary path out of base: %s", coreManagedBinaryPath)
	}
	if !pathWithinBase(coreConfigPath, base) {
		return fmt.Errorf("core config path out of base: %s", coreConfigPath)
	}
	logBase := filepath.Join(base, "logs")
	if !pathWithinBase(coreLogPath, logBase) {
		return fmt.Errorf("core log path out of logs base: %s", coreLogPath)
	}
	return nil
}

func pathWithinBase(path, base string) bool {
	path = filepath.Clean(strings.TrimSpace(path))
	base = filepath.Clean(strings.TrimSpace(base))
	if path == "" || base == "" || !filepath.IsAbs(path) || !filepath.IsAbs(base) {
		return false
	}
	if path == base {
		return true
	}
	return strings.HasPrefix(path, base+string(os.PathSeparator))
}

func consoleHomeDirBestEffort(uid uint32) string {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil && strings.HasPrefix(strings.TrimSpace(u.HomeDir), "/Users/") {
		return u.HomeDir
	}
	sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if sudoUser != "" {
		return filepath.Join("/Users", sudoUser)
	}
	return ""
}

func loadStateBestEffort(path string, logger *log.Logger) desiredState {
	b, err := os.ReadFile(path)
	if err != nil {
		return desiredState{}
	}
	var s desiredState
	parseErr := json.Unmarshal(b, &s)
	if parseErr == nil {
		return cloneDesiredState(s)
	}
	var old legacyDesiredState
	if err := json.Unmarshal(b, &old); err == nil {
		migrated := desiredState{}
		if old.Proxy != nil && old.Proxy.Service != "" {
			migrated.Proxy = map[string]proxyDesired{
				old.Proxy.Service: {
					Service:   old.Proxy.Service,
					Host:      old.Proxy.Host,
					Port:      old.Proxy.Port,
					HTTPPort:  old.Proxy.Port,
					HTTPSPort: old.Proxy.Port,
					SOCKSPort: old.Proxy.Port,
					Enabled:   old.Proxy.Enabled,
				},
			}
		}
		if old.DNS != nil && old.DNS.Service != "" {
			migrated.DNS = map[string]dnsDesired{
				old.DNS.Service: {
					Service: old.DNS.Service,
					Servers: append([]string(nil), old.DNS.Servers...),
				},
			}
		}
		if old.TUN != nil {
			tun := *old.TUN
			migrated.TUN = &tun
		}
		logger.Printf("migrated legacy state file to multi-service format")
		return migrated
	}
	logger.Printf("ignore bad state file: %v", parseErr)
	return desiredState{}
}

func cloneDesiredState(in desiredState) desiredState {
	out := desiredState{}
	if len(in.Proxy) > 0 {
		out.Proxy = make(map[string]proxyDesired, len(in.Proxy))
		for k, v := range in.Proxy {
			out.Proxy[k] = v
		}
	}
	if len(in.DNS) > 0 {
		out.DNS = make(map[string]dnsDesired, len(in.DNS))
		for k, v := range in.DNS {
			out.DNS[k] = dnsDesired{
				Service: v.Service,
				Servers: append([]string(nil), v.Servers...),
			}
		}
	}
	if in.TUN != nil {
		tun := *in.TUN
		out.TUN = &tun
	}
	return out
}

func trimStateForMinimalScope(in desiredState) desiredState {
	out := cloneDesiredState(in)
	out.DNS = nil
	out.TUN = nil
	return out
}

func trimBaselineForMinimalScope(in baselineState) baselineState {
	out := in
	out.DNS = nil
	out.TUN = nil
	return out
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
	stateCopy := cloneDesiredState(h.state)
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
	mux.HandleFunc("/v1/proxy/enable", h.withGuards("proxy_enable", h.enableProxy))
	mux.HandleFunc("/v1/proxy/disable", h.withGuards("proxy_disable", h.disableProxy))
	mux.HandleFunc("/v1/version", h.withGuards("version", h.versionInfo))
	mux.HandleFunc("/v1/startup/check", h.withGuards("startup_check", h.startupCheck))
	mux.HandleFunc("/v1/core/start", h.withGuards("core_start", h.coreStart))
	mux.HandleFunc("/v1/core/stop", h.withGuards("core_stop", h.coreStop))
	mux.HandleFunc("/v1/core/restart", h.withGuards("core_restart", h.coreRestart))
	mux.HandleFunc("/v1/core/status", h.withGuards("core_status", h.coreStatus))
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
		if ci.PID <= 0 {
			h.auditf(action, ci, false, "caller pid unavailable")
			h.writeErr(w, http.StatusForbidden, "FORBIDDEN_CALLER", "forbidden caller")
			return
		}
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
		if !secureTokenMatch(h.token, r.Header.Get("X-Helper-Token")) {
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

func (h *helper) enableProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	ci := h.callerFromReq(r)
	var req setProxyReq
	if err := decodeJSON(r.Body, &req); err != nil {
		h.auditf("proxy_enable", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	service, err := h.resolveService(req.Service)
	if err != nil {
		h.auditf("proxy_enable", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}
	req.Service = service
	webPort, secPort, socksPort, err := resolveProxyPorts(req)
	if !validProxyHost(req.Host) || err != nil {
		h.auditf("proxy_enable", ci, false, "invalid proxy host/port")
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
		curSocksOn, curSocksHost, curSocksPort, err := h.getSOCKSProxyConfig(req.Service)
		if err != nil {
			return err
		}
		if curWebOn && curSecOn && curSocksOn &&
			curWebHost == req.Host && curSecHost == req.Host && curSocksHost == req.Host &&
			curWebPort == webPort && curSecPort == secPort && curSocksPort == socksPort {
			noop = true
			return nil
		}

		snap := proxySnapshot{
			WebEnabled:   curWebOn,
			WebHost:      curWebHost,
			WebPort:      curWebPort,
			SecEnabled:   curSecOn,
			SecHost:      curSecHost,
			SecPort:      curSecPort,
			SocksEnabled: curSocksOn,
			SocksHost:    curSocksHost,
			SocksPort:    curSocksPort,
		}
		if err := h.applyProxy(req.Service, req.Host, webPort, secPort, socksPort, true); err != nil {
			_ = h.restoreProxy(req.Service, snap)
			return err
		}

		h.stateMu.Lock()
		if h.state.Proxy == nil {
			h.state.Proxy = map[string]proxyDesired{}
		}
		h.state.Proxy[req.Service] = proxyDesired{
			Service:   req.Service,
			Host:      req.Host,
			Port:      webPort,
			HTTPPort:  webPort,
			HTTPSPort: secPort,
			SOCKSPort: socksPort,
			Enabled:   true,
		}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("proxy_enable", ci, false, "apply failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("proxy_enable", ci, true, "noop")
		h.writeNoop(w, "proxy already matches target")
		return
	}

	h.auditf("proxy_enable", ci, true, fmt.Sprintf("service=%s host=%s http=%d https=%d socks=%d", req.Service, req.Host, webPort, secPort, socksPort))
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
		h.auditf("proxy_disable", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	service, err := h.resolveService(req.Service)
	if err != nil {
		h.auditf("proxy_disable", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "INVALID_SERVICE", err.Error())
		return
	}
	req.Service = service

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
		curSocksOn, curSocksHost, curSocksPort, err := h.getSOCKSProxyConfig(req.Service)
		if err != nil {
			return err
		}
		if !curWebOn && !curSecOn && !curSocksOn {
			noop = true
			return nil
		}
		snap := proxySnapshot{
			WebEnabled:   curWebOn,
			WebHost:      curWebHost,
			WebPort:      curWebPort,
			SecEnabled:   curSecOn,
			SecHost:      curSecHost,
			SecPort:      curSecPort,
			SocksEnabled: curSocksOn,
			SocksHost:    curSocksHost,
			SocksPort:    curSocksPort,
		}
		if err := h.applyProxy(req.Service, "", 0, 0, 0, false); err != nil {
			_ = h.restoreProxy(req.Service, snap)
			return err
		}

		h.stateMu.Lock()
		if h.state.Proxy == nil {
			h.state.Proxy = map[string]proxyDesired{}
		}
		h.state.Proxy[req.Service] = proxyDesired{Service: req.Service, Enabled: false}
		h.stateMu.Unlock()
		h.saveState()
		return nil
	})
	if opErr != nil {
		h.auditf("proxy_disable", ci, false, "disable failed, rolled back: "+opErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "TXN_APPLY_FAILED", opErr.Error())
		return
	}
	if noop {
		h.auditf("proxy_disable", ci, true, "noop")
		h.writeNoop(w, "proxy already disabled")
		return
	}

	h.auditf("proxy_disable", ci, true, "service="+req.Service)
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true})
}

func (h *helper) versionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Data: map[string]any{"version": h.build}})
}

func (h *helper) startupCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	h.writeJSON(w, http.StatusOK, jsonResp{
		OK:   true,
		Data: h.startupCheckData(),
	})
}

func (h *helper) startupCheckData() map[string]any {
	h.policyMu.RLock()
	p := h.policy
	h.policyMu.RUnlock()

	paths := map[string]startupPathStatus{
		"token":      collectStartupPathStatus(tokenPath),
		"socket":     collectStartupPathStatus(socketPath),
		"policy":     collectStartupPathStatus(policyPath),
		"state":      collectStartupPathStatus(statePath),
		"baseline":   collectStartupPathStatus(baselinePath),
		"coreData":   collectStartupPathStatus(coreDataDir),
		"coreBinary": collectStartupPathStatus(coreManagedBinaryPath),
		"coreConfig": collectStartupPathStatus(coreConfigPath),
		"coreLog":    collectStartupPathStatus(coreLogPath),
		"corePID":    collectStartupPathStatus(corePIDPath),
		"coreLock":   collectStartupPathStatus(coreLockPath),
	}

	routes := []string{
		"/health",
		"/v1/proxy/enable",
		"/v1/proxy/disable",
		"/v1/version",
		"/v1/startup/check",
		"/v1/core/start",
		"/v1/core/stop",
		"/v1/core/restart",
		"/v1/core/status",
	}

	corePolicyErr := ""
	if err := validateCoreRuntimePaths(); err != nil {
		corePolicyErr = err.Error()
	}

	return map[string]any{
		"time":  time.Now(),
		"paths": paths,
		"policySummary": map[string]any{
			"allowedUIDs":                p.AllowedUIDs,
			"clientUIDs":                 policyClientUIDs(p),
			"allowedClientPathPrefixes":  len(p.AllowedClientPathPrefixes),
			"enableCallerPathConstraint": p.EnableCallerPathConstraint,
		},
		"runtimeSummary": map[string]any{
			"coreArgs":      append([]string(nil), coreArgsTemplate...),
			"corePathValid": corePolicyErr == "",
			"corePathError": corePolicyErr,
			"routes":        routes,
		},
	}
}

func collectStartupPathStatus(path string) startupPathStatus {
	s := startupPathStatus{Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s
		}
		s.Error = err.Error()
		return s
	}
	s.Exists = true
	s.Mode = fi.Mode().String()
	s.IsDir = fi.IsDir()
	s.IsSocket = fi.Mode()&os.ModeSocket != 0
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.Owner = fmt.Sprintf("%d:%d", st.Uid, st.Gid)
	}
	s.ACL = aclSummary(path)
	return s
}

func aclSummary(path string) string {
	out, err := exec.Command("/bin/ls", "-lde", path).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func (h *helper) coreStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	running, pid, bin := coreRunningFromPIDFile()
	if !running && pid > 1 {
		_ = os.Remove(corePIDPath)
	}
	if bin == "" {
		bin, _ = selectCoreBinary()
	}
	args := append([]string(nil), coreArgsTemplate...)
	if running {
		if rec, err := readCorePIDRecord(); err == nil && rec.PID == pid && len(rec.Args) > 0 {
			args = append([]string(nil), rec.Args...)
		}
	}
	h.writeJSON(w, http.StatusOK, jsonResp{
		OK: true,
		Data: coreStatusData{
			Running: running,
			PID:     pid,
			Binary:  bin,
			Args:    args,
			Time:    time.Now(),
		},
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
	var req struct {
		ConfigPath string `json:"configPath"`
		Config     string `json:"config"`
	}
	if err := decodeOptionalJSON(r.Body, &req); err != nil {
		h.auditf("core_start", ci, false, err.Error())
		h.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	configPathReq := strings.TrimSpace(req.ConfigPath)
	if configPathReq == "" {
		configPathReq = strings.TrimSpace(req.Config)
	}

	running, pid, _ := coreRunningFromPIDFile()
	if running {
		h.auditf("core_start", ci, true, fmt.Sprintf("noop pid=%d", pid))
		h.writeNoop(w, "core already running")
		return
	}
	startedConfigPath, err := h.startCoreLocked(configPathReq)
	if err != nil {
		h.auditf("core_start", ci, false, err.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_START_FAILED", err.Error())
		return
	}
	h.auditf("core_start", ci, true, "started config="+startedConfigPath)
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
	restartConfigPath := ""
	if rec, err := readCorePIDRecord(); err == nil && rec.PID == pid && len(rec.Args) >= 4 {
		for i := 0; i+1 < len(rec.Args); i++ {
			if rec.Args[i] == "-f" {
				restartConfigPath = strings.TrimSpace(rec.Args[i+1])
				break
			}
		}
	}
	if wasRunning {
		if err := h.stopCoreLocked(pid); err != nil {
			h.auditf("core_restart", ci, false, "stop failed: "+err.Error())
			h.writeErr(w, http.StatusInternalServerError, "CORE_RESTART_FAILED", err.Error())
			return
		}
	}
	startErr := error(nil)
	if wasRunning && oldBinary != "" {
		_, startErr = h.startCoreWithBinaryLocked(oldBinary, restartConfigPath)
	} else {
		_, startErr = h.startCoreLocked("")
	}
	if startErr != nil {
		h.auditf("core_restart", ci, false, "start failed: "+startErr.Error())
		h.writeErr(w, http.StatusInternalServerError, "CORE_RESTART_FAILED", startErr.Error())
		return
	}
	h.auditf("core_restart", ci, true, "restarted")
	h.writeJSON(w, http.StatusOK, jsonResp{OK: true, Message: "core restarted"})
}

func (h *helper) startCoreLocked(configPathReq string) (string, error) {
	bin, err := selectCoreBinary()
	if err != nil {
		return "", err
	}
	return h.startCoreWithBinaryLocked(bin, configPathReq)
}

func (h *helper) startCoreWithBinaryLocked(bin string, configPathReq string) (string, error) {
	if err := validateCoreRuntimePaths(); err != nil {
		return "", err
	}
	if !isAllowedCoreBinary(bin) {
		return "", errors.New("binary path not allowed")
	}
	configPath, err := resolveCoreConfigPath(configPathReq)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(coreDataDir, 0o755); err != nil {
		return "", fmt.Errorf("create core data dir: %w", err)
	}
	if err := validateCoreStartInputs(bin, configPath); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(corePIDPath), 0o700); err != nil {
		return "", err
	}
	coreArgs := []string{
		"-d", coreDataDir,
		"-f", configPath,
	}

	lockf, err := os.OpenFile(coreLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	if err := syscall.Flock(int(lockf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockf.Close()
		return "", errors.New("core lock is held")
	}

	logf, err := os.OpenFile(coreLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return "", err
	}
	cmd := exec.Command(bin, coreArgs...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return "", err
	}
	rec := corePIDRecord{
		PID:       cmd.Process.Pid,
		Binary:    bin,
		StartedAt: time.Now().Format(time.RFC3339),
		Args:      append([]string(nil), coreArgs...),
	}
	pidBytes, _ := json.Marshal(rec)
	if err := writeFileAtomic(corePIDPath, append(pidBytes, '\n'), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_ = logf.Close()
		_ = syscall.Flock(int(lockf.Fd()), syscall.LOCK_UN)
		_ = lockf.Close()
		return "", err
	}
	h.coreLock = lockf
	go h.watchCoreExit(cmd, logf, lockf)
	return configPath, nil
}

func resolveCoreConfigPath(configPathReq string) (string, error) {
	req := strings.TrimSpace(configPathReq)
	if req == "" {
		return coreConfigPath, nil
	}
	configBase := filepath.Join(coreUserHomeDir, "Library", "Application Support", "ClashFox", "config")
	cfg := req
	if filepath.IsAbs(req) {
		cfg = filepath.Clean(req)
	} else {
		cfg = filepath.Clean(filepath.Join(configBase, req))
	}
	if !pathWithinBase(cfg, configBase) {
		return "", fmt.Errorf("core config path out of base: %s", cfg)
	}
	return cfg, nil
}

func validateCoreStartInputs(bin string, configPath string) error {
	if fi, err := os.Lstat(bin); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("core binary path must not be symlink")
		}
	}
	st, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("core binary not accessible: %w", err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return errors.New("core binary is not executable")
	}

	if fi, err := os.Lstat(configPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("core config path must not be symlink")
		}
	}
	cfg, err := os.Stat(configPath)
	if err != nil {
		return fmt.Errorf("core config not accessible: %w", err)
	}
	if cfg.IsDir() {
		return errors.New("core config path is a directory")
	}

	data, err := os.Stat(coreDataDir)
	if err != nil {
		return fmt.Errorf("core data dir not accessible: %w", err)
	}
	if !data.IsDir() {
		return errors.New("core data path is not a directory")
	}

	logDir := filepath.Dir(coreLogPath)
	logDirInfo, err := os.Stat(logDir)
	if err != nil {
		return fmt.Errorf("core log dir not accessible: %w", err)
	}
	if !logDirInfo.IsDir() {
		return errors.New("core log dir is not a directory")
	}

	if fi, err := os.Lstat(coreLogPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("core log path must not be symlink")
		}
		if fi.IsDir() {
			return errors.New("core log path must be a file")
		}
	}
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
	if pidAlive(pid) {
		return errors.New("core process still alive after SIGKILL")
	}
	_ = os.Remove(corePIDPath)
	h.releaseCoreLockLocked()
	return nil
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

func (h *helper) resolveService(service string) (string, error) {
	service = strings.TrimSpace(service)
	if service != "" {
		return service, h.validateService(service)
	}
	return h.detectPrimaryService()
}

func (h *helper) detectPrimaryService() (string, error) {
	services, err := h.availableServices()
	if err != nil {
		return "", err
	}

	routeOut, err := h.runAllowed(cmdRoute, "-n", "get", "default")
	if err == nil {
		iface := parseDefaultRouteInterface(routeOut)
		if iface != "" {
			orderOut, oErr := h.runAllowed(cmdNetworkSetup, "-listnetworkserviceorder")
			if oErr == nil {
				order := parseNetworkServiceOrder(orderOut)
				for _, ent := range order {
					if ent.Device == iface {
						if _, ok := services[ent.Service]; ok {
							return ent.Service, nil
						}
					}
				}
			}
		}
	}

	preferred := []string{"Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"}
	for _, name := range preferred {
		if _, ok := services[name]; ok {
			return name, nil
		}
	}

	var all []string
	for name := range services {
		all = append(all, name)
	}
	sort.Strings(all)
	if len(all) > 0 {
		return all[0], nil
	}
	return "", errors.New("no network services found")
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

func parseDefaultRouteInterface(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) == "interface" {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func parseNetworkServiceOrder(out []byte) []serviceOrderEntry {
	var entries []serviceOrderEntry
	lines := strings.Split(string(out), "\n")
	var currentService string
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		const marker = "Device:"
		if currentService != "" {
			if idx := strings.Index(line, marker); idx >= 0 {
				device := strings.TrimSpace(strings.TrimSuffix(line[idx+len(marker):], ")"))
				if device != "" {
					entries = append(entries, serviceOrderEntry{
						Service: currentService,
						Device:  device,
					})
				}
				currentService = ""
				continue
			}
		}
		if strings.HasPrefix(line, "(") {
			end := strings.Index(line, ")")
			if end >= 0 && end+1 < len(line) {
				svc := strings.TrimSpace(line[end+1:])
				svc = strings.TrimPrefix(svc, "*")
				svc = strings.TrimSpace(svc)
				currentService = svc
			}
			continue
		}
	}
	return entries
}

func resolveProxyPorts(req setProxyReq) (webPort, secPort, socksPort int, err error) {
	httpKebab, err := mergedPortValue(req.HTTPPort, req.HTTPPortKebab, "httpPort")
	if err != nil {
		return 0, 0, 0, err
	}
	httpsKebab, err := mergedPortValue(req.HTTPSPort, req.HTTPSPortKebab, "httpsPort")
	if err != nil {
		return 0, 0, 0, err
	}
	socksKebab, err := mergedPortValue(req.SOCKSPort, req.SOCKSPortKebab, "socksPort")
	if err != nil {
		return 0, 0, 0, err
	}
	mixed, err := mergedPortValue(req.MixedPort, req.MixedPortKebab, "mixedPort")
	if err != nil {
		return 0, 0, 0, err
	}

	webPort = firstNonZero(httpKebab, req.Port)
	secPort = httpsKebab
	socksPort = socksKebab

	// If only mixed-port is provided, use it for all protocols.
	if webPort == 0 && secPort == 0 && socksPort == 0 && mixed > 0 {
		webPort, secPort, socksPort = mixed, mixed, mixed
	} else {
		if webPort == 0 {
			webPort = mixed
		}
		if secPort == 0 {
			secPort = firstNonZero(webPort, mixed)
		}
		if socksPort == 0 {
			socksPort = firstNonZero(webPort, mixed)
		}
	}

	if !validPort(webPort) || !validPort(secPort) || !validPort(socksPort) {
		return 0, 0, 0, errors.New("invalid proxy port")
	}
	return webPort, secPort, socksPort, nil
}

func mergedPortValue(a, b int, field string) (int, error) {
	if a > 0 && b > 0 && a != b {
		return 0, fmt.Errorf("conflicting %s values", field)
	}
	return firstNonZero(a, b), nil
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func validPort(port int) bool {
	return port > 0 && port <= 65535
}

func desiredProxyPorts(in proxyDesired) (webPort, secPort, socksPort int) {
	webPort = firstNonZero(in.HTTPPort, in.Port)
	secPort = firstNonZero(in.HTTPSPort, webPort)
	socksPort = firstNonZero(in.SOCKSPort, webPort)
	return
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
	socksEnabled, socksHost, socksPort, err := h.getSOCKSProxyConfig(service)
	if err != nil {
		return proxySnapshot{}, err
	}
	return proxySnapshot{
		WebEnabled:   webEnabled,
		WebHost:      webHost,
		WebPort:      webPort,
		SecEnabled:   secEnabled,
		SecHost:      secHost,
		SecPort:      secPort,
		SocksEnabled: socksEnabled,
		SocksHost:    socksHost,
		SocksPort:    socksPort,
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
	if s.SocksEnabled {
		if err := h.setSOCKSProxy(service, s.SocksHost, s.SocksPort, true); err != nil {
			return err
		}
	} else {
		if err := h.setSOCKSProxy(service, "", 0, false); err != nil {
			return err
		}
	}
	return nil
}

func (h *helper) applyProxy(service, host string, webPort, secPort, socksPort int, enable bool) error {
	if err := h.setOneProxy(service, false, host, webPort, enable); err != nil {
		return err
	}
	if err := h.setOneProxy(service, true, host, secPort, enable); err != nil {
		return err
	}
	if err := h.setSOCKSProxy(service, host, socksPort, enable); err != nil {
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

func (h *helper) getSOCKSProxyConfig(service string) (enabled bool, host string, port int, err error) {
	out, err := h.runAllowed(cmdNetworkSetup, "-getsocksfirewallproxy", service)
	if err != nil {
		return false, "", 0, err
	}
	return parseProxyConfigOutput(out)
}

func (h *helper) setSOCKSProxy(service string, host string, port int, enable bool) error {
	if enable {
		if _, err := h.runAllowed(cmdNetworkSetup, "-setsocksfirewallproxy", service, host, strconv.Itoa(port)); err != nil {
			return err
		}
		_, err := h.runAllowed(cmdNetworkSetup, "-setsocksfirewallproxystate", service, "on")
		return err
	}
	_, err := h.runAllowed(cmdNetworkSetup, "-setsocksfirewallproxystate", service, "off")
	return err
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

func policyClientUIDs(p policy) []uint32 {
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, uid := range p.AllowedUIDs {
		if uid == 0 {
			continue
		}
		if _, ok := seen[uid]; ok {
			continue
		}
		seen[uid] = struct{}{}
		out = append(out, uid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func setACL(path string, mode os.FileMode, uids []uint32, perms string) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	_ = exec.Command("/bin/chmod", "-N", path).Run()
	for _, uid := range uids {
		subject := strconv.FormatUint(uint64(uid), 10)
		if u, err := user.LookupId(subject); err == nil && u.Username != "" {
			subject = u.Username
		}
		rule := fmt.Sprintf("user:%s allow %s", subject, perms)
		if out, err := exec.Command("/bin/chmod", "+a", rule, path).CombinedOutput(); err != nil {
			return fmt.Errorf("set acl failed for %s uid=%d: %v (%s)", path, uid, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (h *helper) enforceTokenPermissions() error {
	h.policyMu.RLock()
	p := h.policy
	h.policyMu.RUnlock()
	uids := policyClientUIDs(p)
	return setACL(tokenPath, 0o600, uids, "read")
}

func (h *helper) enforceSocketPermissions(path string) error {
	h.policyMu.RLock()
	p := h.policy
	h.policyMu.RUnlock()
	uids := policyClientUIDs(p)
	return setACL(path, 0o600, uids, "read,write")
}

func secureTokenMatch(expect, got string) bool {
	expect = strings.TrimSpace(expect)
	got = strings.TrimSpace(got)
	if expect == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expect), []byte(got)) == 1
}

func prepareSocketPath(path string) error {
	fi, err := os.Lstat(path)
	if err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket path: %s", path)
		}
		return os.Remove(path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

const (
	cmdNetworkSetup = "networksetup"
	cmdRoute        = "route"
)

func (h *helper) runAllowed(kind string, args ...string) ([]byte, error) {
	if h.commandRunner != nil {
		return h.commandRunner(kind, args...)
	}
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
			"-listallnetworkservices":     {},
			"-listnetworkserviceorder":    {},
			"-setwebproxy":                {},
			"-setsecurewebproxy":          {},
			"-setsocksfirewallproxy":      {},
			"-setwebproxystate":           {},
			"-setsecurewebproxystate":     {},
			"-setsocksfirewallproxystate": {},
			"-getwebproxy":                {},
			"-getsecurewebproxy":          {},
			"-getsocksfirewallproxy":      {},
		}
		if _, ok := allowed[sub]; !ok {
			return "", fmt.Errorf("networksetup subcommand not allowed: %s", sub)
		}
		return "/usr/sbin/networksetup", nil
	case cmdRoute:
		joined := strings.Join(args, " ")
		if joined != "-n get default" {
			return "", errors.New("route args not allowed")
		}
		return "/sbin/route", nil
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
	// Ensure there is exactly one JSON value in the body.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid json: trailing data")
	}
	return nil
}

func decodeOptionalJSON(r io.Reader, dst any) error {
	b, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	return decodeJSON(strings.NewReader(string(b)), dst)
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
	stateCopy := cloneDesiredState(h.state)
	h.stateMu.RUnlock()
	b, _ := json.Marshal(stateCopy)
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
	s := cloneDesiredState(h.state)
	h.stateMu.RUnlock()

	for svc, proxy := range s.Proxy {
		service := svc
		want := proxy
		if want.Service != "" {
			service = want.Service
		}
		_ = h.withServiceLock(service, func() error {
			wantWebPort, wantSecPort, wantSocksPort := desiredProxyPorts(want)
			enabledWeb, webHost, webPort, err1 := h.getProxyConfig(service, false)
			enabledSec, secHost, secPort, err2 := h.getProxyConfig(service, true)
			enabledSocks, socksHost, socksPort, err3 := h.getSOCKSProxyConfig(service)
			if err1 != nil || err2 != nil || err3 != nil {
				return nil
			}
			if want.Enabled {
				if !enabledWeb || !enabledSec || !enabledSocks ||
					webHost != want.Host || secHost != want.Host || socksHost != want.Host ||
					webPort != wantWebPort || secPort != wantSecPort || socksPort != wantSocksPort {
					h.driftf(
						"proxy",
						service,
						fmt.Sprintf("enabled=true host=%s http=%d https=%d socks=%d", want.Host, wantWebPort, wantSecPort, wantSocksPort),
						fmt.Sprintf(
							"web_enabled=%t web_host=%s web_port=%d sec_enabled=%t sec_host=%s sec_port=%d socks_enabled=%t socks_host=%s socks_port=%d",
							enabledWeb, webHost, webPort, enabledSec, secHost, secPort, enabledSocks, socksHost, socksPort,
						),
					)
					if err := h.applyProxy(service, want.Host, wantWebPort, wantSecPort, wantSocksPort, true); err != nil {
						h.log.Printf("self-heal proxy apply failed: %v", err)
					} else {
						h.log.Printf("self-heal proxy reapplied for service=%s", service)
					}
				}
			} else {
				if enabledWeb || enabledSec || enabledSocks {
					h.driftf(
						"proxy",
						service,
						"enabled=false",
						fmt.Sprintf("web_enabled=%t sec_enabled=%t socks_enabled=%t", enabledWeb, enabledSec, enabledSocks),
					)
					if err := h.applyProxy(service, "", 0, 0, 0, false); err != nil {
						h.log.Printf("self-heal proxy disable failed: %v", err)
					} else {
						h.log.Printf("self-heal proxy disabled for service=%s", service)
					}
				}
			}
			return nil
		})
	}
}
