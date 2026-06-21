package messageSender

import (
	"encoding/json"
	"fmt"

	"github.com/komari-monitor/komari/database"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/utils/messageSender/factory"
)

// SendEventWithProvider sends one event through a named, already-configured
// provider without replacing the panel's active notification provider. It is
// used for the optional email copy of security alerts.
func SendEventWithProvider(name string, event models.EventMessage) error {
	enabled, err := config.GetAs[bool](config.NotificationEnabledKey, false)
	if err != nil || !enabled {
		return err
	}
	saved, err := database.GetMessageSenderConfigByName(name)
	if err != nil {
		return err
	}
	constructor, ok := factory.GetConstructor(name)
	if !ok {
		return fmt.Errorf("message sender provider not found: %s", name)
	}
	provider := constructor()
	if err := json.Unmarshal([]byte(saved.Addition), provider.GetConfiguration()); err != nil {
		return fmt.Errorf("failed to load config for provider %s: %w", name, err)
	}
	if err := provider.Init(); err != nil {
		return err
	}
	defer provider.Destroy()

	if eventSender, ok := provider.(factory.IEventMessageSender); ok {
		for attempt := 0; attempt < 3; attempt++ {
			if err = eventSender.SendEvent(event); err == nil {
				return nil
			}
		}
		return err
	}
	template, err := config.GetAs[string](config.NotificationTemplateKey, "{{emoji}}{{emoji}}{{emoji}}\nEvent: {{event}}\nClients: {{client}}\nMessage: {{message}}\nTime: {{time}}")
	if err != nil {
		return err
	}
	message := parseTemplate(template, event)
	for attempt := 0; attempt < 3; attempt++ {
		if err = provider.SendTextMessage(message, event.Event); err == nil {
			return nil
		}
	}
	return err
}
