package officialtraffic

import (
	"strings"
	"testing"
	"time"
)

func TestParseBandwagonSnapshot(t *testing.T) {
	body := []byte(`{
		"data_counter": 1920,
		"plan_monthly_data": 2000,
		"monthly_data_multiplier": 1048576,
		"data_next_reset": 1780000000
	}`)

	snapshot, err := parseBandwagonSnapshot("node-1", SourceConfig{Provider: "bandwagon"}, body)
	if err != nil {
		t.Fatalf("parseBandwagonSnapshot returned error: %v", err)
	}

	if snapshot.ClientUUID != "node-1" {
		t.Fatalf("unexpected uuid: %s", snapshot.ClientUUID)
	}
	if snapshot.UsedBytes != 1920*1048576 {
		t.Fatalf("unexpected used bytes: %d", snapshot.UsedBytes)
	}
	if snapshot.LimitBytes != 2000*1048576 {
		t.Fatalf("unexpected limit bytes: %d", snapshot.LimitBytes)
	}
	if snapshot.RemainingBytes != 80*1048576 {
		t.Fatalf("unexpected remaining bytes: %d", snapshot.RemainingBytes)
	}
	if snapshot.ResetAt.IsZero() || snapshot.ResetAt.Unix() != 1780000000 {
		t.Fatalf("unexpected reset time: %s", snapshot.ResetAt.Format(time.RFC3339))
	}
}

func TestParseBandwagonSnapshotCapsNegativeRemaining(t *testing.T) {
	body := []byte(`{
		"data_counter": 2200,
		"plan_monthly_data": 2000,
		"monthly_data_multiplier": 1048576
	}`)

	snapshot, err := parseBandwagonSnapshot("node-1", SourceConfig{Provider: "bandwagon"}, body)
	if err != nil {
		t.Fatalf("parseBandwagonSnapshot returned error: %v", err)
	}
	if snapshot.RemainingBytes != 0 {
		t.Fatalf("remaining should be capped at zero, got %d", snapshot.RemainingBytes)
	}
}

func TestParseBandwagonSnapshotProviderError(t *testing.T) {
	_, err := parseBandwagonSnapshot("node-1", SourceConfig{Provider: "bandwagon"}, []byte(`{"error":"invalid api key"}`))
	if err == nil {
		t.Fatal("expected provider error")
	}
}

func TestRedactSensitiveError(t *testing.T) {
	raw := `Get "https://api.64clouds.com/v1/getServiceInfo?api_key=private_secret&veid=123": context deadline exceeded`
	got := redactSensitive(raw)
	if got == raw {
		t.Fatal("expected redacted error")
	}
	if strings.Contains(got, "private_secret") {
		t.Fatalf("unexpected secret in output: %s", got)
	}
	if got != `Get "https://api.64clouds.com/v1/getServiceInfo?api_key=***&veid=123": context deadline exceeded` {
		t.Fatalf("unexpected redacted error: %s", got)
	}
}
