// Package telegrambot implements a single, panel-side Telegram command bot.
// Agents remain outbound-only and never receive Telegram credentials or commands.
package telegrambot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/config"
	telegramprovider "github.com/komari-monitor/komari/utils/messageSender/telegram"
	"github.com/komari-monitor/komari/utils/notifier"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

const (
	defaultEndpoint = "https://api.telegram.org/bot"
	maxNodes        = 30
)

var manager struct {
	sync.Mutex
	cancel      context.CancelFunc
	fingerprint string
}

type bot struct {
	baseURL         string
	chatID          int64
	threadID        int64
	allowedUsers    map[int64]struct{}
	location        *time.Location
	client          *http.Client
	commandTimezone string
}

type telegramUser struct {
	ID    int64 `json:"id"`
	IsBot bool  `json:"is_bot"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

type telegramMessage struct {
	MessageID       int64         `json:"message_id"`
	MessageThreadID int64         `json:"message_thread_id"`
	From            *telegramUser `json:"from"`
	Chat            telegramChat  `json:"chat"`
	Text            string        `json:"text"`
}

type callbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message"`
	Data    string           `json:"data"`
}

type update struct {
	UpdateID      int64            `json:"update_id"`
	Message       *telegramMessage `json:"message"`
	CallbackQuery *callbackQuery   `json:"callback_query"`
}

type apiResponse[T any] struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      T      `json:"result"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

// Reload stops the existing poller and starts one matching the active Telegram
// provider configuration. Calling Reload repeatedly with unchanged settings is safe.
func Reload() {
	method, _ := config.GetAs[string](config.NotificationMethodKey, "none")
	if method != "telegram" {
		stopIfRunning()
		return
	}

	provider, err := database.GetMessageSenderConfigByName("telegram")
	if err != nil {
		log.Printf("Telegram command menu disabled: cannot load provider: %v", err)
		stopIfRunning()
		return
	}
	var addition telegramprovider.Addition
	if err := json.Unmarshal([]byte(provider.Addition), &addition); err != nil {
		log.Printf("Telegram command menu disabled: invalid provider configuration: %v", err)
		stopIfRunning()
		return
	}
	if !addition.CommandMenuEnabled {
		stopIfRunning()
		return
	}

	b, err := newBot(addition)
	if err != nil {
		log.Printf("Telegram command menu disabled: %v", err)
		stopIfRunning()
		return
	}
	fingerprint := configFingerprint(addition)

	manager.Lock()
	if manager.cancel != nil && manager.fingerprint == fingerprint {
		manager.Unlock()
		return
	}
	if manager.cancel != nil {
		manager.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.cancel = cancel
	manager.fingerprint = fingerprint
	manager.Unlock()

	go b.run(ctx)
}

// Stop terminates the long poller during server shutdown.
func Stop() { stopIfRunning() }

func stopIfRunning() {
	manager.Lock()
	defer manager.Unlock()
	if manager.cancel != nil {
		manager.cancel()
	}
	manager.cancel = nil
	manager.fingerprint = ""
}

func configFingerprint(addition telegramprovider.Addition) string {
	b, _ := json.Marshal(addition)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newBot(addition telegramprovider.Addition) (*bot, error) {
	if strings.TrimSpace(addition.BotToken) == "" {
		return nil, errors.New("bot token is empty")
	}
	chatID, err := strconv.ParseInt(strings.TrimSpace(addition.ChatID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid Telegram chat ID: %w", err)
	}
	var threadID int64
	if strings.TrimSpace(addition.MessageThreadID) != "" {
		threadID, err = strconv.ParseInt(strings.TrimSpace(addition.MessageThreadID), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid Telegram message thread ID: %w", err)
		}
	}
	allowed, err := parseIDs(addition.CommandAllowedUsers)
	if err != nil {
		return nil, fmt.Errorf("invalid command user allow-list: %w", err)
	}
	tz := strings.TrimSpace(addition.CommandTimezone)
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	location, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("invalid command timezone %q: %w", tz, err)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(addition.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	return &bot{
		baseURL:         endpoint + addition.BotToken,
		chatID:          chatID,
		threadID:        threadID,
		allowedUsers:    allowed,
		location:        location,
		client:          &http.Client{Timeout: 40 * time.Second},
		commandTimezone: tz,
	}, nil
}

func parseIDs(raw string) (map[int64]struct{}, error) {
	result := make(map[int64]struct{})
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("%q is not a positive numeric user ID", value)
		}
		result[id] = struct{}{}
	}
	return result, nil
}

func (b *bot) run(ctx context.Context) {
	if err := b.configureMenu(ctx); err != nil {
		log.Printf("Failed to register Telegram command menu: %v", err)
	}
	log.Printf("Telegram command menu started (timezone=%s)", b.commandTimezone)
	var offset int64
	// Discard commands queued while the panel was stopped. A negative offset asks
	// Telegram for only the newest pending update and confirms older updates.
	if pending, err := b.getUpdates(ctx, -1); err == nil && len(pending) > 0 {
		offset = pending[len(pending)-1].UpdateID + 1
	}
	for ctx.Err() == nil {
		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("Telegram command polling failed: %v", err)
			select {
			case <-ctx.Done():
				break
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, item := range updates {
			if item.UpdateID >= offset {
				offset = item.UpdateID + 1
			}
			b.handleUpdate(ctx, item)
		}
	}
	log.Println("Telegram command menu stopped")
}

func (b *bot) authorized(chatID, threadID int64, user *telegramUser) bool {
	if chatID != b.chatID || user == nil || user.IsBot {
		return false
	}
	if b.threadID != 0 && threadID != b.threadID {
		return false
	}
	if len(b.allowedUsers) == 0 {
		// In a private chat the positive chat ID equals the user ID. Groups must
		// configure an explicit user allow-list.
		return b.chatID > 0 && user.ID == b.chatID
	}
	_, ok := b.allowedUsers[user.ID]
	return ok
}

func (b *bot) handleUpdate(ctx context.Context, item update) {
	if item.Message != nil && b.authorized(item.Message.Chat.ID, item.Message.MessageThreadID, item.Message.From) {
		b.handleCommand(ctx, item.Message.Text)
		return
	}
	callback := item.CallbackQuery
	if callback == nil || callback.Message == nil || !b.authorized(callback.Message.Chat.ID, callback.Message.MessageThreadID, &callback.From) {
		return
	}
	_ = b.answerCallback(ctx, callback.ID)
	b.handleCallback(ctx, callback.Data)
}

func (b *bot) handleCommand(ctx context.Context, text string) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return
	}
	command := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0])
	selector := strings.TrimSpace(strings.Join(fields[1:], " "))
	switch command {
	case "/start", "/help":
		_ = b.send(ctx, helpText(), nil)
	case "/nodes":
		b.sendNodes(ctx)
	case "/today", "/yesterday":
		b.sendRange(ctx, strings.TrimPrefix(command, "/"), selector)
	case "/cycle":
		b.sendCycle(ctx, selector)
	case "/total":
		b.sendTotal(ctx, selector)
	case "/alltotal":
		b.sendAllTotal(ctx)
	case "/remaining":
		b.sendRemaining(ctx, selector)
	case "/reset":
		b.sendReset(ctx, selector)
	case "/status":
		b.sendStatus(ctx, selector)
	case "/report":
		b.sendRange(ctx, "today", selector)
		b.sendCycle(ctx, selector)
	default:
		_ = b.send(ctx, "未知命令。使用 /help 查看菜单。", nil)
	}
}

func (b *bot) handleCallback(ctx context.Context, data string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return
	}
	action, uuid := parts[0], parts[1]
	switch action {
	case "node":
		client, ok := findClient(uuid)
		if !ok {
			_ = b.send(ctx, "节点不存在或已被删除。", nil)
			return
		}
		b.sendNodeCard(ctx, client)
	case "today", "yesterday":
		b.sendRange(ctx, action, uuid)
	case "cycle":
		b.sendCycle(ctx, uuid)
	case "total":
		b.sendTotal(ctx, uuid)
	case "alltotal":
		b.sendAllTotal(ctx)
	case "remaining":
		b.sendRemaining(ctx, uuid)
	case "reset":
		b.sendReset(ctx, uuid)
	case "status":
		b.sendStatus(ctx, uuid)
	}
}

func (b *bot) configureMenu(ctx context.Context) error {
	commands := []map[string]string{
		{"command": "start", "description": "启动 Komari 流量机器人"},
		{"command": "nodes", "description": "选择一台监控机器"},
		{"command": "today", "description": "查询每台机器今日流量"},
		{"command": "yesterday", "description": "查询每台机器昨日流量"},
		{"command": "cycle", "description": "查询当前周期累计流量"},
		{"command": "total", "description": "查询机器累计总流量"},
		{"command": "alltotal", "description": "查询所有机器累计总流量"},
		{"command": "remaining", "description": "查询机器剩余总流量"},
		{"command": "reset", "description": "查询每台机器流量重置日"},
		{"command": "status", "description": "查询机器在线与运行状态"},
		{"command": "report", "description": "立即生成完整流量报告"},
		{"command": "help", "description": "查看命令使用说明"},
	}
	encoded, _ := json.Marshal(commands)
	scope, _ := json.Marshal(map[string]any{"type": "chat", "chat_id": b.chatID})
	if err := b.call(ctx, "setMyCommands", url.Values{
		"commands": {string(encoded)},
		"scope":    {string(scope)},
	}, nil); err != nil {
		return err
	}

	// Telegram exposes the blue command button in private chats when the chat
	// menu button is explicitly set to the commands type.
	if b.chatID > 0 {
		menuButton, _ := json.Marshal(map[string]string{"type": "commands"})
		if err := b.call(ctx, "setChatMenuButton", url.Values{
			"chat_id":     {strconv.FormatInt(b.chatID, 10)},
			"menu_button": {string(menuButton)},
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func (b *bot) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	values := url.Values{
		"offset":          {strconv.FormatInt(offset, 10)},
		"timeout":         {"25"},
		"allowed_updates": {`["message","callback_query"]`},
	}
	var result []update
	if err := b.call(ctx, "getUpdates", values, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (b *bot) send(ctx context.Context, text string, keyboard *inlineKeyboard) error {
	values := url.Values{
		"chat_id":    {strconv.FormatInt(b.chatID, 10)},
		"text":       {text},
		"parse_mode": {"HTML"},
	}
	if b.threadID != 0 {
		values.Set("message_thread_id", strconv.FormatInt(b.threadID, 10))
	}
	if keyboard != nil {
		encoded, _ := json.Marshal(keyboard)
		values.Set("reply_markup", string(encoded))
	}
	return b.call(ctx, "sendMessage", values, nil)
}

func (b *bot) answerCallback(ctx context.Context, id string) error {
	return b.call(ctx, "answerCallbackQuery", url.Values{"callback_query_id": {id}}, nil)
}

func (b *bot) call(ctx context.Context, method string, values url.Values, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/"+method, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram API %s returned HTTP %d", method, resp.StatusCode)
	}
	var raw json.RawMessage
	result := apiResponse[json.RawMessage]{Result: raw}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("Telegram API %s failed: %s", method, result.Description)
	}
	if output != nil && len(result.Result) > 0 && string(result.Result) != "true" {
		if err := json.Unmarshal(result.Result, output); err != nil {
			return err
		}
	}
	return nil
}

func helpText() string {
	return `<b>🤖 Komari 流量助手</b>
━━━━━━━━━━━━━━
<b>📊 流量查询</b>
/today — 今日流量
/yesterday — 昨日流量
/cycle — 当前周期累计
/total — 累计总流量
/alltotal — 所有机器累计总流量
/remaining — 剩余总流量
/reset — 每台机器流量重置日

<b>🖥 节点管理</b>
/nodes — 选择监控机器
/status — 在线与运行状态
/report — 立即生成完整报告

<b>💡 使用提示</b>
命令后可附机器名称或 UUID；不填写时查询全部机器。`
}

func (b *bot) sendNodes(ctx context.Context) {
	list, err := clients.GetAllClientBasicInfo()
	if err != nil {
		_ = b.send(ctx, "读取节点失败。", nil)
		return
	}
	sortClients(list)
	if len(list) == 0 {
		_ = b.send(ctx, "当前没有已添加的监控节点。", nil)
		return
	}
	if len(list) > maxNodes {
		list = list[:maxNodes]
	}
	rows := make([][]inlineButton, 0, (len(list)+1)/2)
	rows = append(rows, []inlineButton{{Text: "🌐 所有机器累计总流量", CallbackData: "alltotal:all"}})
	for i := 0; i < len(list); i += 2 {
		row := []inlineButton{{Text: onlineMark(list[i].UUID) + displayName(list[i]), CallbackData: "node:" + list[i].UUID}}
		if i+1 < len(list) {
			row = append(row, inlineButton{Text: onlineMark(list[i+1].UUID) + displayName(list[i+1]), CallbackData: "node:" + list[i+1].UUID})
		}
		rows = append(rows, row)
	}
	_ = b.send(ctx, "<b>🖥 选择监控机器</b>\n━━━━━━━━━━━━━━\n🟢 在线　⚫ 离线\n\n点击机器名称查看详情：", &inlineKeyboard{InlineKeyboard: rows})
}

func (b *bot) sendNodeCard(ctx context.Context, client models.Client) {
	status := "⚫ 离线"
	if isOnline(client.UUID) {
		status = "🟢 在线"
	}
	text := fmt.Sprintf("<b>🖥 %s</b>\n━━━━━━━━━━━━━━\n<b>状态</b>　%s\n<b>UUID</b>　<code>%s</code>", html.EscapeString(displayName(client)), status, html.EscapeString(client.UUID))
	keyboard := &inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "📊 今日流量", CallbackData: "today:" + client.UUID}, {Text: "📅 昨日流量", CallbackData: "yesterday:" + client.UUID}},
		{{Text: "🔄 当前周期", CallbackData: "cycle:" + client.UUID}, {Text: "🗓 重置日", CallbackData: "reset:" + client.UUID}},
		{{Text: "📊 累计总流量", CallbackData: "total:" + client.UUID}, {Text: "📦 剩余总流量", CallbackData: "remaining:" + client.UUID}},
		{{Text: "🟢 运行状态", CallbackData: "status:" + client.UUID}},
	}}
	_ = b.send(ctx, text, keyboard)
}

func (b *bot) sendRange(ctx context.Context, kind, selector string) {
	now := time.Now().In(b.location)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, b.location)
	label := "今日流量"
	end := now
	if kind == "yesterday" {
		end = start.Add(-time.Nanosecond)
		start = start.AddDate(0, 0, -1)
		label = "昨日流量"
	}
	list, err := selectClients(selector)
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	lines := []string{fmt.Sprintf("<b>📊 %s</b>\n━━━━━━━━━━━━━━", label)}
	for _, client := range list {
		totals, err := notifier.GetClientTrafficTotalsInRange(client.UUID, start, end)
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s：统计失败", html.EscapeString(displayName(client))))
			continue
		}
		lines = append(lines, formatTrafficLine(client, totals))
	}
	lines = append(lines, fmt.Sprintf("\n━━━━━━━━━━━━━━\n🕒 时区　<code>%s</code>", html.EscapeString(b.commandTimezone)))
	_ = b.send(ctx, strings.Join(lines, "\n"), nil)
}

func (b *bot) sendCycle(ctx context.Context, selector string) {
	b.sendCumulative(ctx, selector, "🔄 当前周期累计流量")
}

func (b *bot) sendTotal(ctx context.Context, selector string) {
	b.sendCumulative(ctx, selector, "📊 累计总流量")
}

func (b *bot) sendAllTotal(ctx context.Context) {
	list, err := clients.GetAllClientBasicInfo()
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	sortClients(list)
	reports := agent_runtime.GetLatestReport()
	var up, down int64
	for _, client := range list {
		if report := reports[client.UUID]; report != nil {
			up += report.Network.TotalUp
			down += report.Network.TotalDown
			continue
		}
		if totals, queryErr := notifier.GetLatestClientTrafficTotals(client.UUID); queryErr == nil {
			up += totals.Up
			down += totals.Down
		}
	}
	text := fmt.Sprintf("<b>🌐 所有机器累计总流量</b>\n━━━━━━━━━━━━━━\n　🖥 机器数量　<b>%d</b>\n　⬆️ 上传合计　%s\n　⬇️ 下载合计　%s\n　📦 流量总计　<b>%s</b>\n━━━━━━━━━━━━━━\n<i>各机器重置日可能不同，此处汇总每台机器各自当前周期的累计值。</i>", len(list), humanBytes(up), humanBytes(down), humanBytes(up+down))
	_ = b.send(ctx, text, nil)
}

func (b *bot) sendCumulative(ctx context.Context, selector, title string) {
	list, err := selectClients(selector)
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	latest := agent_runtime.GetLatestReport()
	lines := []string{fmt.Sprintf("<b>%s</b>\n━━━━━━━━━━━━━━", html.EscapeString(title))}
	for _, client := range list {
		totals := notifier.TrafficTotals{}
		if report := latest[client.UUID]; report != nil {
			totals.Up = report.Network.TotalUp
			totals.Down = report.Network.TotalDown
		} else {
			totals, err = notifier.GetLatestClientTrafficTotals(client.UUID)
			if err != nil {
				lines = append(lines, fmt.Sprintf("%s：统计失败", html.EscapeString(displayName(client))))
				continue
			}
		}
		lines = append(lines, formatTrafficLine(client, totals))
	}
	lines = append(lines, "\n━━━━━━━━━━━━━━\n💡 周期边界由探针的 <code>month-rotate</code> 设置决定。")
	_ = b.send(ctx, strings.Join(lines, "\n"), nil)
}

func (b *bot) sendReset(ctx context.Context, selector string) {
	list, err := selectClients(selector)
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	now := time.Now().In(b.location)
	lines := []string{"<b>🗓 流量重置日</b>\n━━━━━━━━━━━━━━"}
	for _, client := range list {
		name := html.EscapeString(displayName(client))
		if client.TrafficResetReported {
			zone := strings.TrimSpace(client.TrafficResetTimezone)
			if zone == "" {
				zone = "Local"
			}
			if client.TrafficResetDay == 0 {
				lines = append(lines, fmt.Sprintf("\n<b>%s</b>\n　⏸ 探针未启用每月流量重置\n　🌐 时区　<code>%s</code>", name, html.EscapeString(zone)))
			} else {
				note := ""
				if client.TrafficResetDay > 28 {
					note = "（短月顺延至下月 1 日）"
				}
				lines = append(lines, fmt.Sprintf("\n<b>%s</b>\n　✅ 探针精确上报\n　📆 每月 <b>%d 日</b>%s\n　🌐 时区　<code>%s</code>", name, client.TrafficResetDay, note, html.EscapeString(zone)))
			}
			continue
		}
		resetAt, found, err := notifier.GetLatestClientTrafficReset(client.UUID, now)
		if err != nil {
			lines = append(lines, fmt.Sprintf("\n<b>%s</b>\n　⚠️ 查询失败", name))
			continue
		}
		if !found {
			lines = append(lines, fmt.Sprintf("\n<b>%s</b>\n　⏳ 近 62 天暂未检测到重置", name))
			continue
		}
		local := resetAt.In(b.location)
		lines = append(lines, fmt.Sprintf("\n<b>%s</b>\n　📆 推测每月 <b>%d 日</b>\n　🕒 最近重置 %s", name, local.Day(), local.Format("2006-01-02 15:04")))
	}
	lines = append(lines, "\n━━━━━━━━━━━━━━\n<i>新版探针显示精确配置；旧版探针降级为历史归零推断。</i>")
	_ = b.send(ctx, strings.Join(lines, "\n"), nil)
}

func (b *bot) sendRemaining(ctx context.Context, selector string) {
	list, err := selectClients(selector)
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	reports := agent_runtime.GetLatestReport()
	lines := []string{"<b>📦 剩余总流量</b>\n━━━━━━━━━━━━━━"}
	for _, client := range list {
		name := html.EscapeString(displayName(client))
		if client.TrafficLimit <= 0 {
			lines = append(lines, fmt.Sprintf("\n<b>🖥 %s</b>\n　⚙️ 面板尚未设置流量上限", name))
			continue
		}
		totals := notifier.TrafficTotals{}
		if report := reports[client.UUID]; report != nil {
			totals.Up = report.Network.TotalUp
			totals.Down = report.Network.TotalDown
		} else if latest, queryErr := notifier.GetLatestClientTrafficTotals(client.UUID); queryErr == nil {
			totals = latest
		}
		used := notifier.ComputeUsedByType(strings.ToLower(client.TrafficLimitType), totals.Up, totals.Down)
		remaining := client.TrafficLimit - used
		if remaining < 0 {
			remaining = 0
		}
		percent := float64(used) / float64(client.TrafficLimit) * 100
		if percent > 100 {
			percent = 100
		}
		lines = append(lines, fmt.Sprintf("\n<b>🖥 %s</b>\n　%s　%.1f%%\n　✅ 剩余　<b>%s</b>\n　📈 已用　%s / %s\n　🧮 口径　<code>%s</code>", name, progressBar(percent), percent, humanBytes(remaining), humanBytes(used), humanBytes(client.TrafficLimit), html.EscapeString(normalizeTrafficLimitType(client.TrafficLimitType))))
	}
	lines = append(lines, "\n━━━━━━━━━━━━━━\n<i>流量上限与统计口径来自面板的节点设置。</i>")
	_ = b.send(ctx, strings.Join(lines, "\n"), nil)
}

func progressBar(percent float64) string {
	filled := int(math.Round(percent / 10))
	if filled < 0 {
		filled = 0
	}
	if filled > 10 {
		filled = 10
	}
	return strings.Repeat("▰", filled) + strings.Repeat("▱", 10-filled)
}

func normalizeTrafficLimitType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "up", "down", "sum", "min", "max":
		return value
	default:
		return "max"
	}
}

func (b *bot) sendStatus(ctx context.Context, selector string) {
	list, err := selectClients(selector)
	if err != nil {
		_ = b.send(ctx, html.EscapeString(err.Error()), nil)
		return
	}
	reports := agent_runtime.GetLatestReport()
	lines := []string{"<b>🖥 机器运行状态</b>\n━━━━━━━━━━━━━━"}
	for _, client := range list {
		state := "⚫ 离线"
		if isOnline(client.UUID) {
			state = "🟢 在线"
		}
		extra := ""
		if report := reports[client.UUID]; report != nil && report.Uptime > 0 {
			extra = " · 运行 " + formatDuration(time.Duration(report.Uptime)*time.Second)
		}
		lines = append(lines, fmt.Sprintf("%s <b>%s</b>%s", state, html.EscapeString(displayName(client)), extra))
	}
	_ = b.send(ctx, strings.Join(lines, "\n"), nil)
}

func selectClients(selector string) ([]models.Client, error) {
	list, err := clients.GetAllClientBasicInfo()
	if err != nil {
		return nil, err
	}
	sortClients(list)
	if strings.TrimSpace(selector) == "" {
		if len(list) > maxNodes {
			list = list[:maxNodes]
		}
		return list, nil
	}
	client, ok := findClientInList(list, selector)
	if !ok {
		return nil, fmt.Errorf("找不到节点 %q", selector)
	}
	return []models.Client{client}, nil
}

func findClient(selector string) (models.Client, bool) {
	list, err := clients.GetAllClientBasicInfo()
	if err != nil {
		return models.Client{}, false
	}
	return findClientInList(list, selector)
}

func findClientInList(list []models.Client, selector string) (models.Client, bool) {
	selector = strings.TrimSpace(selector)
	for _, client := range list {
		if client.UUID == selector || strings.EqualFold(client.Name, selector) {
			return client, true
		}
	}
	var match models.Client
	found := 0
	for _, client := range list {
		if strings.Contains(strings.ToLower(client.Name), strings.ToLower(selector)) {
			match = client
			found++
		}
	}
	return match, found == 1
}

func sortClients(list []models.Client) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Weight != list[j].Weight {
			return list[i].Weight > list[j].Weight
		}
		return strings.ToLower(displayName(list[i])) < strings.ToLower(displayName(list[j]))
	})
}

func displayName(client models.Client) string {
	if strings.TrimSpace(client.Name) != "" {
		return client.Name
	}
	return client.UUID
}

func onlineMark(uuid string) string {
	if isOnline(uuid) {
		return "🟢 "
	}
	return "⚫ "
}

func isOnline(uuid string) bool {
	for _, onlineUUID := range agent_runtime.GetAllOnlineUUIDs() {
		if onlineUUID == uuid {
			return true
		}
	}
	return false
}

func formatTrafficLine(client models.Client, totals notifier.TrafficTotals) string {
	return fmt.Sprintf("\n<b>🖥 %s</b>\n　⬆️ 上传　%s\n　⬇️ 下载　%s\n　📦 合计　<b>%s</b>", html.EscapeString(displayName(client)), humanBytes(totals.Up), humanBytes(totals.Down), humanBytes(totals.Up+totals.Down))
}

func humanBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(value)/float64(div), "KMGTPE"[exp])
}

func formatDuration(value time.Duration) string {
	days := int64(value / (24 * time.Hour))
	hours := int64(value/time.Hour) % 24
	if days > 0 {
		return fmt.Sprintf("%d天%d小时", days, hours)
	}
	minutes := int64(value/time.Minute) % 60
	return fmt.Sprintf("%d小时%d分钟", hours, minutes)
}
