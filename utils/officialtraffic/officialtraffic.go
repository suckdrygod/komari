package officialtraffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/protocol/v1"
)

const (
	ConfigKey              = "official_traffic_sources"
	defaultBandwagonAPIURL = "https://api.64clouds.com/v1/getServiceInfo"
	defaultCacheTTL        = 5 * time.Minute
	requestTimeout         = 8 * time.Second
)

type SourceConfig struct {
	Provider        string `json:"provider"`
	Enabled         bool   `json:"enabled"`
	Endpoint        string `json:"endpoint,omitempty"`
	VEID            string `json:"veid,omitempty"`
	APIKey          string `json:"api_key,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	CacheTTLSeconds int    `json:"cache_ttl_seconds,omitempty"`
}

type Snapshot struct {
	ClientUUID     string
	Provider       string
	SourceName     string
	UsedBytes      int64
	LimitBytes     int64
	RemainingBytes int64
	ResetAt        time.Time
	UpdatedAt      time.Time
}

type cachedSnapshot struct {
	snapshot  Snapshot
	expiresAt time.Time
}

var (
	mu    sync.Mutex
	cache = map[string]cachedSnapshot{}
)

func ResetCacheForTest() {
	mu.Lock()
	defer mu.Unlock()
	cache = map[string]cachedSnapshot{}
}

func GetSnapshot(client models.Client) (*Snapshot, bool) {
	snapshot, ok := GetSnapshotForUUID(client.UUID)
	if !ok {
		return nil, false
	}
	if snapshot.LimitBytes <= 0 && client.TrafficLimit > 0 {
		snapshot.LimitBytes = client.TrafficLimit
		snapshot.RemainingBytes = maxInt64(snapshot.LimitBytes-snapshot.UsedBytes, 0)
	}
	return snapshot, true
}

func GetSnapshotForUUID(uuid string) (*Snapshot, bool) {
	cfg, ok := sourceConfigForUUID(uuid)
	if !ok || !cfg.Enabled {
		return nil, false
	}

	ttl := defaultCacheTTL
	if cfg.CacheTTLSeconds > 0 {
		ttl = time.Duration(cfg.CacheTTLSeconds) * time.Second
	}

	now := time.Now()
	mu.Lock()
	if item, exists := cache[uuid]; exists && now.Before(item.expiresAt) {
		snapshot := item.snapshot
		mu.Unlock()
		return &snapshot, true
	}
	mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	snapshot, err := fetchSnapshot(ctx, uuid, cfg)
	if err != nil {
		slog.Warn("official traffic source fetch failed", "client", uuid, "provider", safeProvider(cfg.Provider), "error", err)
		return nil, false
	}

	mu.Lock()
	cache[uuid] = cachedSnapshot{snapshot: snapshot, expiresAt: now.Add(ttl)}
	mu.Unlock()
	return &snapshot, true
}

func ApplyReportOverride(uuid string, report *v1.Report) bool {
	if report == nil {
		return false
	}
	snapshot, ok := GetSnapshotForUUID(uuid)
	if !ok {
		return false
	}
	report.Network.TotalUp = 0
	report.Network.TotalDown = snapshot.UsedBytes
	return true
}

func sourceConfigForUUID(uuid string) (cfg SourceConfig, ok bool) {
	defer func() {
		if recover() != nil {
			cfg = SourceConfig{}
			ok = false
		}
	}()
	sources, err := config.GetAs[map[string]SourceConfig](ConfigKey)
	if err != nil || len(sources) == 0 {
		return SourceConfig{}, false
	}
	if value, exists := sources[uuid]; exists {
		return value, true
	}
	for key, value := range sources {
		if strings.EqualFold(strings.TrimSpace(key), strings.TrimSpace(uuid)) {
			return value, true
		}
	}
	return SourceConfig{}, false
}

func fetchSnapshot(ctx context.Context, uuid string, cfg SourceConfig) (Snapshot, error) {
	switch normalizeProvider(cfg.Provider) {
	case "bandwagon", "bandwagonhost", "kiwivm", "64clouds":
		return fetchBandwagonSnapshot(ctx, uuid, cfg)
	default:
		return Snapshot{}, fmt.Errorf("unsupported provider %q", safeProvider(cfg.Provider))
	}
}

func fetchBandwagonSnapshot(ctx context.Context, uuid string, cfg SourceConfig) (Snapshot, error) {
	if strings.TrimSpace(cfg.VEID) == "" || strings.TrimSpace(cfg.APIKey) == "" {
		return Snapshot{}, errors.New("missing veid or api key")
	}

	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = defaultBandwagonAPIURL
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return Snapshot{}, fmt.Errorf("invalid endpoint: %w", err)
	}
	q := u.Query()
	q.Set("veid", strings.TrimSpace(cfg.VEID))
	q.Set("api_key", strings.TrimSpace(cfg.APIKey))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Snapshot{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Snapshot{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, err
	}
	return parseBandwagonSnapshot(uuid, cfg, body)
}

func parseBandwagonSnapshot(uuid string, cfg SourceConfig, body []byte) (Snapshot, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return Snapshot{}, err
	}
	if msg := firstString(raw, "error", "message"); strings.TrimSpace(msg) != "" {
		return Snapshot{}, fmt.Errorf("provider error: %s", msg)
	}

	used, ok := numeric(raw, "data_counter", "dataCounter")
	if !ok {
		return Snapshot{}, errors.New("missing data_counter")
	}
	limit, _ := numeric(raw, "plan_monthly_data", "planMonthlyData")
	multiplier, ok := numeric(raw, "monthly_data_multiplier", "monthlyDataMultiplier")
	if !ok || multiplier <= 0 {
		multiplier = 1
	}

	usedBytes := safeInt64(used * multiplier)
	limitBytes := safeInt64(limit * multiplier)
	remainingBytes := int64(0)
	if limitBytes > 0 {
		remainingBytes = maxInt64(limitBytes-usedBytes, 0)
	}
	resetAt := parseResetAt(raw)
	sourceName := strings.TrimSpace(cfg.DisplayName)
	if sourceName == "" {
		sourceName = "BandwagonHost 官方 API"
	}
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		provider = "bandwagon"
	}

	return Snapshot{
		ClientUUID:     uuid,
		Provider:       normalizeProvider(provider),
		SourceName:     sourceName,
		UsedBytes:      usedBytes,
		LimitBytes:     limitBytes,
		RemainingBytes: remainingBytes,
		ResetAt:        resetAt,
		UpdatedAt:      time.Now(),
	}, nil
}

func normalizeProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func safeProvider(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "unknown"
	}
	return normalizeProvider(provider)
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := raw[key]; ok {
			if s, ok := value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func numeric(raw map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return v, true
		case float32:
			return float64(v), true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case json.Number:
			f, err := v.Float64()
			return f, err == nil
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return f, err == nil
		}
	}
	return 0, false
}

func parseResetAt(raw map[string]any) time.Time {
	if n, ok := numeric(raw, "data_next_reset", "dataNextReset"); ok && n > 0 {
		return time.Unix(safeInt64(n), 0)
	}
	for _, key := range []string{"next_reset", "reset_at", "data_reset_at"} {
		if s := firstString(raw, key); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

func safeInt64(f float64) int64 {
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return 0
	}
	if f > float64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(math.Round(f))
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
