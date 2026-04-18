package ct

import "testing"

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		host string
		port string
	}{
		{name: "bare host", raw: "example.com", host: "example.com", port: "443"},
		{name: "https URL", raw: "https://example.com/path?q=1", host: "example.com", port: "443"},
		{name: "explicit port", raw: "https://example.com:8443", host: "example.com", port: "8443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTarget(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Host != tt.host || got.Port != tt.port {
				t.Fatalf("target = %s:%s, want %s:%s", got.Host, got.Port, tt.host, tt.port)
			}
		})
	}
}

func TestNormalizeTargetRejectsUnsupportedInputs(t *testing.T) {
	tests := []string{
		"",
		"http://example.com",
		"https://",
		"https://example.com:notaport",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := normalizeTarget(raw); err == nil {
				t.Fatalf("normalizeTarget(%q) succeeded, want error", raw)
			}
		})
	}
}
