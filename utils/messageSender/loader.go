package messageSender

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/komari-monitor/komari/utils/messageSender/factory"
)

func LoadProvider(name string, addition string) error {
	mu.Lock()
	defer mu.Unlock()
	provider, err := loadProviderInstance(name, addition)
	if err != nil {
		return err
	}
	for _, existing := range currentProviders {
		if existing.provider != nil {
			_ = existing.provider.Destroy()
		}
	}
	if len(currentProviders) == 0 && currentProvider != nil {
		_ = currentProvider.Destroy()
	}
	currentProvider = provider
	currentProviders = []namedProvider{{name: strings.ToLower(strings.TrimSpace(name)), provider: provider}}
	return nil
}

func loadProviderInstance(name string, addition string) (factory.IMessageSender, error) {
	constructor, exists := factory.GetConstructor(name)
	if !exists {
		return nil, fmt.Errorf("message sender provider not found: %s", name)
	}

	provider := constructor()
	err := json.Unmarshal([]byte(addition), provider.GetConfiguration())
	if err != nil {
		return nil, fmt.Errorf("failed to load config for provider %s: %w", name, err)
	}
	if err := provider.Init(); err != nil {
		return nil, err
	}
	return provider, nil
}

func GetProviderConfiguration(name string) (map[string]interface{}, error) {
	constructor, exists := factory.GetConstructor(name)
	if !exists {
		return nil, fmt.Errorf("message sender provider not found: %s", name)
	}

	provider := constructor()
	config := provider.GetConfiguration()

	// 将配置转换为map
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal configuration: %w", err)
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(configBytes, &configMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return configMap, nil
}
