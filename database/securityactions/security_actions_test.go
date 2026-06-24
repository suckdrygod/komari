package securityactions

import (
	"testing"

	"github.com/komari-monitor/komari/pkg/config"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestQueueLifecycle(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	config.SetDb(db)

	first, err := Enqueue("client-1", "203.0.113.9", ActionBan, 60)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	second, err := Enqueue("client-1", "203.0.113.9", ActionBan, 60)
	if err != nil {
		t.Fatalf("enqueue duplicate: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected duplicate pending action to be idempotent")
	}

	pending, err := PendingForClient("client-1")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 || pending[0].Action != ActionBan {
		t.Fatalf("unexpected pending actions: %#v", pending)
	}

	acked, err := Ack("client-1", first.ID, StatusSuccess, "applied")
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if acked.Status != StatusSuccess || acked.Message != "applied" {
		t.Fatalf("unexpected acked action: %#v", acked)
	}

	pending, err = PendingForClient("client-1")
	if err != nil {
		t.Fatalf("pending after ack: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending actions after ack, got %#v", pending)
	}
}
