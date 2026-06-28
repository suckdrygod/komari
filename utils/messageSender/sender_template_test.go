package messageSender

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari/database/models"
	messageevent "github.com/komari-monitor/komari/database/models/messageEvent"
	"github.com/komari-monitor/komari/utils/messageSender/factory"
)

const sshSuccessGlobalTemplate = `🔐 SSH 安全登录提醒
━━━━━━━━━━━━━━
{{message}}

✅ SSH 会话已成功建立
⚠️ 若非本人操作，请立即检查 SSH 密钥、用户权限与登录日志。`

func TestIsolatedEventTemplatesDoNotUseSSHSuccessText(t *testing.T) {
	events := []models.EventMessage{
		{
			Event:   "SSH 爆破告警",
			Clients: []models.Client{{Name: "node-a"}},
			Time:    time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
			Message: "服务器：node-a\n来源 IP：203.0.113.1\n目标用户：root\n认证方式：密码\n失败次数：5\n统计窗口：60 秒\n时间：2026-06-24 16:00:00 北京时间\n\n说明：该告警只代表检测到 SSH 登录失败 / 爆破行为，未执行封禁命令。",
		},
		{
			Event:   "Offline",
			Clients: []models.Client{{Name: "node-b"}},
			Time:    time.Date(2026, 6, 24, 8, 1, 0, 0, time.UTC),
			Message: "机器已离线，超过宽限期 300 秒。",
		},
		{
			Event:   "Online",
			Clients: []models.Client{{Name: "node-c"}},
			Time:    time.Date(2026, 6, 24, 8, 2, 0, 0, time.UTC),
			Message: "机器连接已恢复，当前状态为在线。",
		},
		{
			Event:   "Test",
			Time:    time.Date(2026, 6, 24, 8, 3, 0, 0, time.UTC),
			Message: "This is a test message from Komari.",
		},
		{
			Event:   messageevent.Expire,
			Time:    time.Date(2026, 6, 24, 8, 4, 0, 0, time.UTC),
			Message: "• WEPC美国家宽直播 (7d)",
		},
		{
			Event:   messageevent.Renew,
			Clients: []models.Client{{Name: "node-renew"}},
			Time:    time.Date(2026, 6, 24, 8, 5, 0, 0, time.UTC),
			Message: "• node-renew until 2026-07-24",
		},
		{
			Event:   messageevent.Login,
			Time:    time.Date(2026, 6, 24, 8, 6, 0, 0, time.UTC),
			Message: "password: 203.0.113.10 (US)\nSafari",
		},
		{
			Event:   messageevent.Alert,
			Clients: []models.Client{{Name: "node-load"}},
			Time:    time.Date(2026, 6, 24, 8, 7, 0, 0, time.UTC),
			Message: "CPU high",
		},
		{
			Event:   messageevent.Traffic,
			Clients: []models.Client{{Name: "node-traffic"}},
			Time:    time.Date(2026, 6, 24, 8, 8, 0, 0, time.UTC),
			Message: "used 80%",
		},
		{
			Event:   messageevent.DReport,
			Time:    time.Date(2026, 6, 24, 8, 9, 0, 0, time.UTC),
			Emoji:   "📊",
			Message: "node-a：1 GB",
		},
	}

	for _, event := range events {
		got := formatEventMessage(sshSuccessGlobalTemplate, event)
		assertNotContains(t, got, "SSH 会话已成功建立")
		assertNotContains(t, got, "若非本人操作，请立即检查 SSH 密钥、用户权限与登录日志")
	}
}

func TestSSHSuccessEventUsesSSHSuccessTemplate(t *testing.T) {
	got := formatEventMessage("ignored {{message}}", models.EventMessage{
		Event:   "SSH 登录成功",
		Clients: []models.Client{{Name: "node-a"}},
		Time:    time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
		Message: "👤 登录账户：root\n🌐 来源地址：203.0.113.1\n💻 登录终端：ssh\n🔑 认证方式：密钥\n\n🕒 登录时间：2026-06-24 16:00:00 北京时间",
	})

	assertContains(t, got, "🔐 SSH 安全登录提醒")
	assertContains(t, got, "✅ SSH 会话已成功建立")
	assertContains(t, got, "若非本人操作，请立即检查 SSH 密钥、用户权限与登录日志")
	assertContains(t, got, "节点名称：node-a")
}

func TestCustomNonIsolatedEventsStillUseGlobalTemplate(t *testing.T) {
	got := formatEventMessage("global {{event}} {{client}} {{message}}", models.EventMessage{
		Event:   "CustomEvent",
		Clients: []models.Client{{Name: "node-a"}},
		Message: "used 80%",
	})

	assertContains(t, got, "global CustomEvent node-a used 80%")
}

func TestEventDisplayTitleUsesChineseForBuiltInEvents(t *testing.T) {
	cases := map[string]string{
		messageevent.Expire:  "到期提醒",
		messageevent.Renew:   "自动续费通知",
		messageevent.Login:   "面板登录提醒",
		messageevent.Alert:   "负载告警",
		messageevent.Traffic: "流量阈值提醒",
		messageevent.DReport: "每日流量报告",
		messageevent.WReport: "每周流量报告",
		messageevent.MReport: "每月流量报告",
		"CustomEvent":        "CustomEvent",
	}
	for event, want := range cases {
		if got := eventDisplayTitle(models.EventMessage{Event: event}); got != want {
			t.Fatalf("eventDisplayTitle(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestProviderNamesFromValueDedupAndFilter(t *testing.T) {
	got := providerNamesFromValue([]any{"telegram", "email", "telegram", "none", "", "missing-provider"})
	want := []string{"telegram", "email"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("providerNamesFromValue = %#v, want %#v", got, want)
	}
}

func TestProviderNamesFromJSONListString(t *testing.T) {
	got := providerNamesFromValue(`["telegram","email","telegram"]`)
	want := []string{"telegram", "email"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("providerNamesFromValue = %#v, want %#v", got, want)
	}
}

func TestSendTextMessageToProvidersSucceedsIfOneChannelSucceeds(t *testing.T) {
	tg := &fakeSender{name: "telegram"}
	email := &fakeSender{name: "email", textErr: errors.New("smtp failed")}
	var logs []string

	err := sendTextMessageToProviders([]namedProvider{
		{name: "telegram", provider: tg},
		{name: "email", provider: email},
	}, "hello", "Test", func(_, _, message, level string) {
		logs = append(logs, level+":"+message)
	})

	if err != nil {
		t.Fatalf("expected overall success when one provider succeeds, got %v", err)
	}
	if tg.textCalls != 1 || email.textCalls != 3 {
		t.Fatalf("unexpected text calls: telegram=%d email=%d", tg.textCalls, email.textCalls)
	}
	assertJoinedContains(t, logs, "info:Message sent via telegram: Test")
	assertJoinedContains(t, logs, "error:Failed to send message via email")
}

func TestSendTextMessageToProvidersFailsIfAllChannelsFail(t *testing.T) {
	tg := &fakeSender{name: "telegram", textErr: errors.New("tg failed")}
	email := &fakeSender{name: "email", textErr: errors.New("smtp failed")}

	err := sendTextMessageToProviders([]namedProvider{
		{name: "telegram", provider: tg},
		{name: "email", provider: email},
	}, "hello", "Test", nil)

	if err == nil {
		t.Fatal("expected error when all providers fail")
	}
	assertContains(t, err.Error(), "telegram")
	assertContains(t, err.Error(), "email")
}

func TestSendEventToProvidersSendsSSHAuthGuardToEveryProvider(t *testing.T) {
	tg := &fakeSender{name: "telegram"}
	email := &fakeSender{name: "email"}

	err := sendEventToProviders([]namedProvider{
		{name: "telegram", provider: tg},
		{name: "email", provider: email},
	}, models.EventMessage{
		Event:   "SSH 爆破告警",
		Clients: []models.Client{{Name: "node-a"}},
		Time:    time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC),
		Message: "服务器：node-a\n来源 IP：203.0.113.1\n目标用户：root\n认证方式：密码\n失败次数：5\n统计窗口：60 秒\n时间：2026-06-24 16:00:00 北京时间\n\n说明：该告警只代表检测到 SSH 登录失败 / 爆破行为，未执行封禁命令。",
	}, "{{message}}", nil)

	if err != nil {
		t.Fatalf("expected event success, got %v", err)
	}
	if tg.textCalls != 1 || email.textCalls != 1 {
		t.Fatalf("expected both providers to receive event text once, got telegram=%d email=%d", tg.textCalls, email.textCalls)
	}
	assertContains(t, tg.lastMessage, "🚨 SSH 爆破告警")
	assertContains(t, email.lastMessage, "🚨 SSH 爆破告警")
	assertNotContains(t, tg.lastMessage, "SSH 会话已成功建立")
	assertNotContains(t, email.lastMessage, "SSH 会话已成功建立")
}

func TestShouldSilenceSSHAuthGuardEventOnlyAffectsAuthGuardAlerts(t *testing.T) {
	if !shouldSilenceSSHAuthGuardEvent(models.EventMessage{Event: "SSH 爆破告警"}, true) {
		t.Fatal("expected SSH auth guard alert to be silenced when silent mode is enabled")
	}
	if shouldSilenceSSHAuthGuardEvent(models.EventMessage{Event: "SSH 登录成功"}, true) {
		t.Fatal("SSH login success notifications must not be silenced by auth guard silent mode")
	}
	if shouldSilenceSSHAuthGuardEvent(models.EventMessage{Event: "Offline"}, true) {
		t.Fatal("offline notifications must not be silenced by auth guard silent mode")
	}
	if shouldSilenceSSHAuthGuardEvent(models.EventMessage{Event: "SSH 爆破告警"}, false) {
		t.Fatal("auth guard alert must not be silenced when silent mode is disabled")
	}
}

type fakeSender struct {
	name        string
	textErr     error
	textCalls   int
	lastMessage string
	lastTitle   string
}

func (f *fakeSender) GetName() string {
	return f.name
}

func (f *fakeSender) GetConfiguration() factory.Configuration {
	return &struct{}{}
}

func (f *fakeSender) SendTextMessage(message, title string) error {
	f.textCalls++
	f.lastMessage = message
	f.lastTitle = title
	return f.textErr
}

func (f *fakeSender) Init() error {
	return nil
}

func (f *fakeSender) Destroy() error {
	return nil
}

func assertContains(t *testing.T, text, want string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Fatalf("expected %q to contain %q", text, want)
	}
}

func assertNotContains(t *testing.T, text, want string) {
	t.Helper()
	if strings.Contains(text, want) {
		t.Fatalf("expected %q not to contain %q", text, want)
	}
}

func assertJoinedContains(t *testing.T, lines []string, want string) {
	t.Helper()
	assertContains(t, strings.Join(lines, "\n"), want)
}
