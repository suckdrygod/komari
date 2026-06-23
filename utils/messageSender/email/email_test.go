package email

import "testing"

func TestBuildSenderAddressUsesFromName(t *testing.T) {
	addr, header := buildSenderAddress("noreply@example.com", "Komari Monitor")

	if addr != "noreply@example.com" {
		t.Fatalf("sender address = %q, want noreply@example.com", addr)
	}
	if header != `"Komari Monitor" <noreply@example.com>` {
		t.Fatalf("sender header = %q", header)
	}
}

func TestBuildSenderAddressEncodesNonASCIIFromName(t *testing.T) {
	addr, header := buildSenderAddress("noreply@example.com", "Komari 监控")

	if addr != "noreply@example.com" {
		t.Fatalf("sender address = %q, want noreply@example.com", addr)
	}
	if header != "=?utf-8?q?Komari_=E7=9B=91=E6=8E=A7?= <noreply@example.com>" {
		t.Fatalf("sender header = %q", header)
	}
}

func TestBuildSenderAddressPreservesExistingDisplayNameWhenFromNameEmpty(t *testing.T) {
	addr, header := buildSenderAddress(`"Existing Name" <noreply@example.com>`, "")

	if addr != "noreply@example.com" {
		t.Fatalf("sender address = %q, want noreply@example.com", addr)
	}
	if header != `"Existing Name" <noreply@example.com>` {
		t.Fatalf("sender header = %q", header)
	}
}
