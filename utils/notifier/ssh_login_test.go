package notifier

import (
	"testing"
	"time"

	v2 "github.com/komari-monitor/komari/protocol/v2"
	"github.com/stretchr/testify/assert"
)

func TestNotifySSHLoginRejectsUnsafeInputBeforeLookup(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tests := []v2.SSHLoginParams{
		{User: "root<script>", RemoteIP: "203.0.113.5", RemotePort: 22, AuthMethod: "publickey", OccurredAt: now},
		{User: "root", RemoteIP: "not-an-ip", RemotePort: 22, AuthMethod: "publickey", OccurredAt: now},
		{User: "root", RemoteIP: "203.0.113.5", RemotePort: 0, AuthMethod: "publickey", OccurredAt: now},
		{User: "root", RemoteIP: "203.0.113.5", RemotePort: 22, AuthMethod: "unknown", OccurredAt: now},
		{User: "root", RemoteIP: "203.0.113.5", RemotePort: 22, AuthMethod: "publickey", OccurredAt: "invalid"},
	}
	for _, params := range tests {
		assert.Error(t, NotifySSHLogin("missing-client", params))
	}
}

func TestAllowSSHLoginEventRateLimit(t *testing.T) {
	clientUUID := "rate-limit-test"
	now := time.Now()
	for i := 0; i < 10; i++ {
		assert.True(t, allowSSHLoginEvent(clientUUID, now.Add(time.Duration(i)*time.Millisecond)))
	}
	assert.False(t, allowSSHLoginEvent(clientUUID, now.Add(time.Second)))
	assert.True(t, allowSSHLoginEvent(clientUUID, now.Add(2*time.Minute)))
}
