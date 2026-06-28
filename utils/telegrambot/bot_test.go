package telegrambot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/models"
	telegramprovider "github.com/komari-monitor/komari/utils/messageSender/telegram"
	"github.com/komari-monitor/komari/utils/notifier"
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
	assert.Equal(t, 13, commandCount)
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

func TestResetStatusForReportedClients(t *testing.T) {
	b := &bot{location: time.UTC}

	configured := b.resetStatusForClient(models.Client{TrafficResetReported: true, TrafficResetDay: 31}, time.Now())
	assert.Equal(t, resetStatusConfigured, configured.Kind)
	assert.Equal(t, "每月 31 日（短月顺延）", configured.Text)

	disabled := b.resetStatusForClient(models.Client{TrafficResetReported: true, TrafficResetDay: 0}, time.Now())
	assert.Equal(t, resetStatusDisabled, disabled.Kind)
	assert.Equal(t, "未启用", disabled.Text)
}

func TestFormatResetListLine(t *testing.T) {
	client := models.Client{Name: "VPS <01>"}

	assert.Equal(t, "✅ <b>VPS &lt;01&gt;</b> — 每月 11 日", formatResetListLine(client, resetStatus{Kind: resetStatusConfigured, Text: "每月 11 日"}))
	assert.Equal(t, "➖ <b>VPS &lt;01&gt;</b> — 未启用", formatResetListLine(client, resetStatus{Kind: resetStatusDisabled, Text: "未启用"}))
	assert.Equal(t, "🧭 <b>VPS &lt;01&gt;</b> — 推测每月 1 日", formatResetListLine(client, resetStatus{Kind: resetStatusInferred, Text: "推测每月 1 日"}))
	assert.Equal(t, "❔ <b>VPS &lt;01&gt;</b> — 暂未检测到", formatResetListLine(client, resetStatus{Kind: resetStatusUnknown, Text: "暂未检测到"}))
}

func TestChunkTelegramMessage(t *testing.T) {
	lines := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		lines = append(lines, strings.Repeat("机器", 20))
	}

	chunks := chunkTelegramMessage("<b>header</b>\n\n", lines)

	require.Greater(t, len(chunks), 1)
	for _, chunk := range chunks {
		assert.LessOrEqual(t, len(chunk), 3800)
	}
}

func TestNodesPagePanelPaginates(t *testing.T) {
	list := make([]models.Client, 0, nodePageSize+1)
	for i := 0; i < nodePageSize+1; i++ {
		list = append(list, models.Client{UUID: fmt.Sprintf("uuid-%02d", i), Name: fmt.Sprintf("Node %02d", i)})
	}

	text, keyboard := nodesPagePanel(list, 0)

	assert.Contains(t, text, "第 1/2 页")
	require.NotNil(t, keyboard)
	assert.Contains(t, keyboard.InlineKeyboard[len(keyboard.InlineKeyboard)-2][0].Text, "1/2")
	assert.Equal(t, "下一页 ➡️", keyboard.InlineKeyboard[len(keyboard.InlineKeyboard)-2][1].Text)
}

func TestMainMenuKeyboard(t *testing.T) {
	keyboard := mainMenuKeyboard()

	require.NotNil(t, keyboard)
	assert.Equal(t, "menu:traffic", keyboard.InlineKeyboard[0][0].CallbackData)
	assert.Equal(t, "nodes:0", keyboard.InlineKeyboard[0][1].CallbackData)
	assert.Equal(t, "report:", keyboard.InlineKeyboard[2][0].CallbackData)
}

func TestRenderMainMenuText(t *testing.T) {
	text := renderMainMenuText(menuStats{
		Total:           12,
		Online:          10,
		Limited:         7,
		ResetConfigured: 5,
		Timezone:        "Asia/Shanghai",
	})

	assert.Contains(t, text, "Komari 流量控制台")
	assert.Contains(t, text, "在线：<b>10 / 12</b>")
	assert.Contains(t, text, "限额：<b>7</b>")
	assert.Contains(t, text, "重置日：<b>5</b>")
}

func TestTruncateButtonText(t *testing.T) {
	assert.Equal(t, "短名称", truncateButtonText("短名称"))
	assert.True(t, strings.HasSuffix(truncateButtonText(strings.Repeat("长", 40)), "…"))
}

func TestCompactTrafficCards(t *testing.T) {
	client := models.Client{Name: "VPS <01>"}
	totals := notifier.TrafficTotals{Up: 12 * 1024 * 1024, Down: 608 * 1024 * 1024}

	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n🔼 上传: 12.00 MB\n🔽 下载: 608.00 MB\n📊 今日: <b>620.00 MB</b>", formatTrafficCard(client, totals, "今日"))
	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n⚠️ 流量统计失败", formatTrafficErrorCard(client))
	assert.Equal(t, "🖥️ 机器: <b>全部机器（2 台）</b>\n━━━━━━━━━━━━━━\n🔼 上传: 1.00 KB\n🔽 下载: 2.00 KB\n📊 总计: <b>3.00 KB</b>", formatAllTrafficCard(2, 1024, 2048))
	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n━━━━━━━━━━━━━━\n📈 已用: 600.00 MB / 1000.00 MB\n📦 剩余: <b>400.00 MB</b>\n🎯 状态: 🟢 安全　60.0%\n▰▰▰▰▰▰▱▱▱▱", formatRemainingCard(client, 600*1024*1024, 400*1024*1024, 1000*1024*1024, false))
	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n━━━━━━━━━━━━━━\n📈 已用: 600.00 MB\n📦 剩余: <b>∞ 无限</b>\n📊 总量: ∞ 无限\n🎯 状态: ⚪ 未设置流量上限", formatRemainingCard(client, 600*1024*1024, 0, 0, true))
	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n━━━━━━━━━━━━━━\n🔄 重置: 每月 1 日", formatResetCard(client, "每月 1 日"))
	assert.Equal(t, "🖥️ 机器: <b>VPS &lt;01&gt;</b>\n🔼 上传: 12.00 MB\n🔽 下载: 608.00 MB\n📊 周期: <b>620.00 MB</b>\n📡 官方源: 暂不可用，已回退探针数据", formatTrafficCardWithNote(client, totals, "周期", "📡 官方源: 暂不可用，已回退探针数据"))
	assert.Equal(t, "▰▰▰▰▰▰▱▱▱▱", progressBar(60))
	icon, text := trafficUsageStatus(92)
	assert.Equal(t, "🔴", icon)
	assert.Equal(t, "危险", text)
}

func TestCapTrafficTotals(t *testing.T) {
	capped := capTrafficTotals(
		notifier.TrafficTotals{Up: 275 * 1024, Down: 329 * 1024},
		notifier.TrafficTotals{Up: 9 * 1024, Down: 12 * 1024},
	)

	assert.Equal(t, notifier.TrafficTotals{Up: 9 * 1024, Down: 12 * 1024}, capped)

	unchanged := capTrafficTotals(
		notifier.TrafficTotals{Up: 5 * 1024, Down: 6 * 1024},
		notifier.TrafficTotals{Up: 9 * 1024, Down: 12 * 1024},
	)

	assert.Equal(t, notifier.TrafficTotals{Up: 5 * 1024, Down: 6 * 1024}, unchanged)
}
