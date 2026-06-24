package messageSender

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/utils/messageSender/factory"
)

var (
	currentProvider  factory.IMessageSender
	currentProviders []namedProvider
	mu               = sync.Mutex{}
	once             = sync.Once{}
)

type namedProvider struct {
	name     string
	provider factory.IMessageSender
}

func CurrentProvider() factory.IMessageSender {
	mu.Lock()
	defer mu.Unlock()
	return currentProvider
}

func activeProviders() []namedProvider {
	mu.Lock()
	defer mu.Unlock()
	providers := make([]namedProvider, len(currentProviders))
	copy(providers, currentProviders)
	return providers
}

func Initialize() {
	go func() {
		once.Do(func() {
			all := factory.GetAllMessageSenders()
			for _, provider := range all {
				if _, err := database.GetMessageSenderConfigByName(provider.GetName()); err == nil {
					continue
				}
				// 如果数据库中没有该提供者的配置，则保存默认配置
				config := provider.GetConfiguration()
				configBytes, err := json.Marshal(config)
				if err != nil {
					log.Printf("Failed to marshal config for provider %s: %v", provider.GetName(), err)
					return
				}
				if err := database.SaveMessageSenderConfig(&models.MessageSenderProvider{
					Name:     provider.GetName(),
					Addition: string(configBytes),
				}); err != nil {
					log.Printf("Failed to save default config for provider %s: %v", provider.GetName(), err)
					return
				}
			}
		})
	}()

	names := ConfiguredProviderNames()
	providers := make([]namedProvider, 0, len(names))
	for _, name := range names {
		senderConfig, err := database.GetMessageSenderConfigByName(name)
		if err != nil {
			log.Printf("Message sender provider %s is not configured: %v", name, err)
			continue
		}
		provider, err := loadProviderInstance(name, senderConfig.Addition)
		if err != nil {
			log.Printf("Failed to load message sender provider %s: %v", name, err)
			continue
		}
		providers = append(providers, namedProvider{name: name, provider: provider})
	}

	replaceCurrentProviders(providers)
}

func replaceCurrentProviders(providers []namedProvider) {
	mu.Lock()
	defer mu.Unlock()
	for _, existing := range currentProviders {
		if existing.provider != nil {
			_ = existing.provider.Destroy()
		}
	}
	if len(currentProviders) == 0 && currentProvider != nil {
		_ = currentProvider.Destroy()
	}
	currentProviders = providers
	if len(providers) > 0 {
		currentProvider = providers[0].provider
		return
	}
	empty, err := loadProviderInstance("empty", "{}")
	if err != nil {
		currentProvider = nil
		return
	}
	currentProvider = empty
}

func ConfiguredProviderNames() []string {
	raw, err := config.Get(config.NotificationMethodsKey)
	if err == nil {
		return providerNamesFromValue(raw)
	}
	method, _ := config.GetAs[string](config.NotificationMethodKey, "none")
	return providerNamesFromValue(method)
}

func IsProviderConfigured(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "none" {
		return false
	}
	for _, providerName := range ConfiguredProviderNames() {
		if providerName == name {
			return true
		}
	}
	return false
}

func providerNamesFromValue(raw any) []string {
	var values []string
	switch v := raw.(type) {
	case []string:
		values = append(values, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			break
		}
		if strings.HasPrefix(text, "[") {
			var parsed []string
			if err := json.Unmarshal([]byte(text), &parsed); err == nil {
				values = append(values, parsed...)
				break
			}
		}
		values = append(values, strings.Split(text, ",")...)
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || value == "none" || seen[value] {
			continue
		}
		if _, ok := factory.GetConstructor(value); !ok {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func SendTextMessage(message string, title string) error {
	providers := activeProviders()
	if CurrentProvider() == nil {
		return fmt.Errorf("message sender provider is not initialized")
	}
	var err error
	NotificationEnabled, err := config.GetAs[bool](config.NotificationEnabledKey, false)
	if err != nil {
		return err
	}
	if !NotificationEnabled {
		return nil
	}
	if len(providers) == 0 {
		return nil
	}
	return sendTextMessageToProviders(providers, message, title, auditlog.Log)
}

func SendEvent(event models.EventMessage) error {
	providers := activeProviders()
	if CurrentProvider() == nil {
		return fmt.Errorf("message sender provider is not initialized")
	}
	var err error
	cfg, err := config.GetMany(map[string]any{
		config.NotificationEnabledKey:    false,
		config.NotificationTemplateKey:   "{{emoji}}{{emoji}}{{emoji}}\nEvent: {{event}}\nClients: {{client}}\nMessage: {{message}}\nTime: {{time}}",
		config.SSHAuthGuardSilentModeKey: true,
	})
	if err != nil {
		return err
	}
	if !cfg[config.NotificationEnabledKey].(bool) {
		return nil
	}
	if shouldSilenceSSHAuthGuardEvent(event, cfg[config.SSHAuthGuardSilentModeKey]) {
		auditlog.EventLog("info", "SSH auth guard alert notification suppressed: reason=silent_mode")
		return nil
	}
	if len(providers) == 0 {
		return nil
	}
	messageTemplate := cfg[config.NotificationTemplateKey].(string)
	return sendEventToProviders(providers, event, messageTemplate, auditlog.Log)
}

func shouldSilenceSSHAuthGuardEvent(event models.EventMessage, silentMode any) bool {
	enabled, ok := silentMode.(bool)
	return ok && enabled && event.Event == "SSH 爆破告警"
}

type auditLogger func(ip, uuid, message, msgType string)

func sendTextMessageToProviders(providers []namedProvider, message, title string, audit auditLogger) error {
	var errs []error
	success := false
	for _, provider := range providers {
		if provider.provider == nil {
			continue
		}
		err := sendTextMessageToProvider(provider.provider, message, title)
		if err == nil {
			success = true
			if audit != nil {
				audit("", "", "Message sent via "+provider.name+": "+title, "info")
			}
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %w", provider.name, err))
		if audit != nil {
			audit("", "", "Failed to send message via "+provider.name+" after 3 attempts: "+err.Error()+","+title, "error")
		}
	}
	if success {
		return nil
	}
	return errors.Join(errs...)
}

func sendEventToProviders(providers []namedProvider, event models.EventMessage, messageTemplate string, audit auditLogger) error {
	var errs []error
	success := false
	for _, provider := range providers {
		if provider.provider == nil {
			continue
		}
		err := sendEventToProvider(provider.provider, event, messageTemplate)
		if err == nil {
			success = true
			if audit != nil {
				audit("", "", "Event message sent via "+provider.name+": "+event.Event, "info")
			}
			continue
		}
		errs = append(errs, fmt.Errorf("%s: %w", provider.name, err))
		if audit != nil {
			audit("", "", "Failed to send event message via "+provider.name+" after 3 attempts: "+err.Error()+","+event.Event, "error")
		}
	}
	if success {
		return nil
	}
	return errors.Join(errs...)
}

func sendTextMessageToProvider(provider factory.IMessageSender, message, title string) error {
	var err error
	for i := 0; i < 3; i++ {
		err = provider.SendTextMessage(message, title)
		if isSuccessfulSendError(err) {
			return nil
		}
	}
	return err
}

func sendEventToProvider(provider factory.IMessageSender, event models.EventMessage, messageTemplate string) error {
	if eventSender, ok := provider.(factory.IEventMessageSender); ok {
		var err error
		for i := 0; i < 3; i++ {
			err = eventSender.SendEvent(event)
			if isSuccessfulSendError(err) {
				return nil
			}
		}
		return err
	}
	return sendTextMessageToProvider(provider, formatEventMessage(messageTemplate, event), event.Event)
}

func isSuccessfulSendError(err error) bool {
	return err == nil || err.Error() == "short response: \x00\x00\x00\x1a\x00\x00\x00"
}

func formatEventMessage(messageTemplate string, event models.EventMessage) string {
	if isolated, ok := isolatedEventTemplate(event); ok {
		return isolated
	}
	return parseTemplate(messageTemplate, event)
}

func isolatedEventTemplate(event models.EventMessage) (string, bool) {
	clientText := eventClientText(event)
	timeText := formatEventTime(event.Time)

	switch event.Event {
	case "SSH 登录成功":
		return strings.Join([]string{
			"🔐 SSH 安全登录提醒",
			"━━━━━━━━━━━━━━",
			"🖥️ 节点名称：" + clientText,
			"📌 登录事件：SSH 登录成功",
			"",
			event.Message,
			"",
			"━━━━━━━━━━━━━━",
			"✅ SSH 会话已成功建立",
			"⚠️ 若非本人操作，请立即检查 SSH 密钥、用户权限与登录日志。",
		}, "\n"), true
	case "SSH 爆破告警":
		return strings.Join([]string{
			"🚨 SSH 爆破告警",
			"━━━━━━━━━━━━━━",
			event.Message,
		}, "\n"), true
	case "Offline":
		return strings.Join([]string{
			"🔴 机器离线告警",
			"━━━━━━━━━━━━━━",
			"🖥️ 节点名称：" + clientText,
			"📌 事件类型：Offline",
			"📝 详细说明：" + event.Message,
			"🕒 时间：" + timeText,
		}, "\n"), true
	case "Online":
		return strings.Join([]string{
			"🟢 机器恢复通知",
			"━━━━━━━━━━━━━━",
			"🖥️ 节点名称：" + clientText,
			"📌 事件类型：Online",
			"📝 详细说明：" + event.Message,
			"🕒 时间：" + timeText,
		}, "\n"), true
	case "Test":
		return strings.Join([]string{
			"🧪 Test",
			"━━━━━━━━━━━━━━",
			"📌 事件类型：Test",
			"📝 详细说明：" + event.Message,
			"🕒 时间：" + timeText,
		}, "\n"), true
	default:
		return "", false
	}
}

func eventClientText(event models.EventMessage) string {
	clientNames := make([]string, 0, len(event.Clients))
	for _, c := range event.Clients {
		name := c.Name
		if strings.TrimSpace(name) == "" {
			name = c.UUID
		}
		if strings.TrimSpace(name) != "" {
			clientNames = append(clientNames, name)
		}
	}
	if len(clientNames) == 0 {
		return "-"
	}
	return strings.Join(clientNames, ", ")
}

func formatEventTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.Format(time.RFC3339)
}

func parseTemplate(messageTemplate string, event models.EventMessage) string {
	// Aggregate client names. If Name is empty, fall back to UUID.
	joinedClients := eventClientText(event)

	replaceMap := map[string]string{
		"{{event}}":   event.Event,
		"{{client}}":  joinedClients,
		"{{time}}":    event.Time.Format(time.RFC3339),
		"{{message}}": event.Message,
		"{{emoji}}":   event.Emoji,
	}
	result := messageTemplate
	for placeholder, value := range replaceMap {
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}
