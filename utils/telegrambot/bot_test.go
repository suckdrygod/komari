package telegrambot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	telegramprovider "github.com/komari-monitor/komari/utils/messageSender/telegram"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIDs(t *testing.T) {
	ids, err := parseIDs("123, 456,123")
	require.NoError(t, err)
	assert.Len(t, ids, 2)
	_, ok := ids[456]
	assert.True(t, ok)

	_, err = parseIDs("123,not-a-number")
	assert.Error(t, err)
}

func TestAuthorizationRequiresExplicitUsersForGroups(t *testing.T) {
	b := &bot{chatID: -100123, allowedUsers: map[int64]struct{}{}}
	assert.False(t, b.authorized(-100123, 0, &telegramUser{ID: 42}))

	b.allowedUsers[42] = struct{}{}
	assert.True(t, b.authorized(-100123, 0, &telegramUser{ID: 42}))
	assert.False(t, b.authorized(-100123, 0, &telegramUser{ID: 43}))
	assert.False(t, b.authorized(-100999, 0, &telegramUser{ID: 42}))
}

func TestAuthorizationAllowsMatchingPrivateChat(t *testing.T) {
	b := &bot{chatID: 42, allowedUsers: map[int64]struct{}{}}
	assert.True(t, b.authorized(42, 0, &telegramUser{ID: 42}))
	assert.False(t, b.authorized(42, 0, &telegramUser{ID: 43}))

	b.threadID = 7
	assert.False(t, b.authorized(42, 8, &telegramUser{ID: 42}))
	assert.True(t, b.authorized(42, 7, &telegramUser{ID: 42}))
}

func TestSetCommandsAndGetUpdates(t *testing.T) {
	var commandCount int
	var menuButtonSet bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		values, err := url.ParseQuery(string(body))
		require.NoError(t, err)

		switch {
		case strings.HasSuffix(r.URL.Path, "/setMyCommands"):
			var commands []map[string]string
			require.NoError(t, json.Unmarshal([]byte(values.Get("commands")), &commands))
			commandCount = len(commands)
			assert.Contains(t, values.Get("scope"), `"type":"chat"`)
			_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
		case strings.HasSuffix(r.URL.Path, "/setChatMenuButton"):
			assert.Equal(t, "42", values.Get("chat_id"))
			assert.JSONEq(t, `{"type":"commands"}`, values.Get("menu_button"))
			menuButtonSet = true
			_, _ = io.WriteString(w, `{"ok":true,"result":true}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			assert.Equal(t, "25", values.Get("timeout"))
			_, _ = io.WriteString(w, `{"ok":true,"result":[{"update_id":99,"message":{"from":{"id":42},"chat":{"id":42},"text":"/today"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	b := &bot{baseURL: server.URL + "/bot-token", chatID: 42, client: server.Client()}
	require.NoError(t, b.configureMenu(context.Background()))
	assert.Equal(t, 12, commandCount)
	assert.True(t, menuButtonSet)

	updates, err := b.getUpdates(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, updates, 1)
	assert.Equal(t, int64(99), updates[0].UpdateID)
	assert.Equal(t, "/today", updates[0].Message.Text)
}

func TestNewBotDefaultsAndValidation(t *testing.T) {
	b, err := newBot(telegramprovider.Addition{
		BotToken:            "secret",
		ChatID:              "42",
		CommandTimezone:     "Asia/Shanghai",
		CommandAllowedUsers: "42,43",
	})
	require.NoError(t, err)
	assert.Equal(t, defaultEndpoint+"secret", b.baseURL)
	assert.Equal(t, int64(42), b.chatID)
	assert.Equal(t, 8*time.Hour, timezoneOffset(t, b.location))

	_, err = newBot(telegramprovider.Addition{BotToken: "secret", ChatID: "invalid"})
	assert.Error(t, err)
}

func timezoneOffset(t *testing.T, location *time.Location) time.Duration {
	t.Helper()
	_, offset := time.Date(2026, 6, 21, 12, 0, 0, 0, location).Zone()
	return time.Duration(offset) * time.Second
}

func TestHumanBytes(t *testing.T) {
	assert.Equal(t, "0 B", humanBytes(-1))
	assert.Equal(t, "1.00 KB", humanBytes(1024))
	assert.Equal(t, "1.50 GB", humanBytes(3*1024*1024*1024/2))
}

func TestProgressBarAndTrafficLimitType(t *testing.T) {
	assert.Equal(t, "▰▰▰▰▰▱▱▱▱▱", progressBar(50))
	assert.Equal(t, "max", normalizeTrafficLimitType(""))
	assert.Equal(t, "sum", normalizeTrafficLimitType("SUM"))
}
