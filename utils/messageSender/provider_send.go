package messageSender

import (
	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/config"
)

// SendEventAndEmailCopy is kept for older notifier call sites. Multi-provider
// fan-out now lives in SendEvent itself.
func SendEventAndEmailCopy(event models.EventMessage) error {
	return SendEvent(event)
}

// SendEventWithProvider sends one event through a named, already-configured
// provider without replacing the panel's active notification provider.
func SendEventWithProvider(name string, event models.EventMessage) error {
	enabled, err := config.GetAs[bool](config.NotificationEnabledKey, false)
	if err != nil || !enabled {
		return err
	}
	saved, err := database.GetMessageSenderConfigByName(name)
	if err != nil {
		return err
	}
	provider, err := loadProviderInstance(name, saved.Addition)
	if err != nil {
		return err
	}
	defer provider.Destroy()

	template, err := config.GetAs[string](config.NotificationTemplateKey, "{{emoji}}{{emoji}}{{emoji}}\nEvent: {{event}}\nClients: {{client}}\nMessage: {{message}}\nTime: {{time}}")
	if err != nil {
		return err
	}
	return sendEventToProvider(provider, event, template)
}
