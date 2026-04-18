package ct

import (
	"context"
	"net/netip"
	"testing"
)

func TestValidatePublicAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "public IPv4", addr: "93.184.216.34"},
		{name: "public IPv6", addr: "2606:2800:220:1:248:1893:25c8:1946"},
		{name: "loopback", addr: "127.0.0.1", wantErr: true},
		{name: "private", addr: "10.1.2.3", wantErr: true},
		{name: "aws metadata", addr: "169.254.169.254", wantErr: true},
		{name: "carrier grade NAT", addr: "100.64.0.1", wantErr: true},
		{name: "documentation IPv4", addr: "192.0.2.1", wantErr: true},
		{name: "unique local IPv6", addr: "fc00::1", wantErr: true},
		{name: "IPv4 mapped loopback", addr: "::ffff:127.0.0.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublicAddr(netip.MustParseAddr(tt.addr))
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePublicAddr(%s) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePublicHostRejectsLocalhostAndUnsafeLiterals(t *testing.T) {
	tests := []string{
		"localhost",
		"api.localhost",
		"127.0.0.1",
		"::1",
	}
	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			if err := validatePublicHost(context.Background(), host); err == nil {
				t.Fatalf("validatePublicHost(%q) succeeded, want error", host)
			}
		})
	}
}
