package main

import "testing"

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
