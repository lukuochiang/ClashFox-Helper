package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

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

func TestParsePFStatusOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "enabled", in: "Status: Enabled for 0 days", want: true},
		{name: "disabled", in: "Status: Disabled", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePFStatusOutput([]byte(tc.in))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %t got %t", tc.want, got)
			}
		})
	}
}

func TestParsePFStatusOutput_Invalid(t *testing.T) {
	if _, err := parsePFStatusOutput([]byte("pfctl output changed")); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestValidCoreCandidate(t *testing.T) {
	ok := []string{"mihomo", "mihomo-v1.19.3", "mihomo_amd64", "mihomo.1"}
	for _, s := range ok {
		if !validCoreCandidate(s) {
			t.Fatalf("expected valid candidate: %s", s)
		}
	}
	bad := []string{"", "../mihomo", "a/b", "mihomo;rm", "with space"}
	for _, s := range bad {
		if validCoreCandidate(s) {
			t.Fatalf("expected invalid candidate: %s", s)
		}
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
