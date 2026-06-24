package securityconsole

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/database/dbcore"
	"github.com/komari-monitor/komari/database/models"
	"github.com/komari-monitor/komari/database/securityactions"
	"github.com/komari-monitor/komari/database/sshlogin"
	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/web/api"
)

const securityIPStatesKey = "security_ip_states"

var (
	authGuardAlertNewRE   = regexp.MustCompile(`^SSH auth guard alert: client=(.*), uuid=([^,]+), ip=([^,]+), user=(.*), method=(.*), count=(\d+)`)
	authGuardAlertOldRE   = regexp.MustCompile(`^SSH auth guard alert: client=(.*), ip=([^,]+), user=(.*), count=(\d+)`)
	authGuardSuppressedRE = regexp.MustCompile(`^SSH auth guard alert suppressed: client=(.*?)(?: uuid=([^ ]+))? ip=([^ ]+) reason=([A-Za-z0-9_-]+)`)
	eventSentRE           = regexp.MustCompile(`^Event message sent via ([^:]+): (.+)$`)
	eventFailedRE         = regexp.MustCompile(`^Failed to send event message via ([^ ]+) .*?,(.+)$`)
)

type IPState struct {
	Status    string `json:"status"`
	Client    string `json:"client,omitempty"`
	IP        string `json:"ip"`
	Reason    string `json:"reason,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type SecurityAttack struct {
	SourceIP    string `json:"source_ip"`
	User        string `json:"user"`
	FailedCount int    `json:"failed_count"`
	Client      string `json:"client"`
	ClientUUID  string `json:"client_uuid,omitempty"`
	Method      string `json:"method"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"`
	Risk        string `json:"risk"`
}

type SecurityEvent struct {
	ID          uint   `json:"id"`
	Type        string `json:"type"`
	SourceIP    string `json:"source_ip,omitempty"`
	User        string `json:"user,omitempty"`
	FailedCount int    `json:"failed_count,omitempty"`
	Client      string `json:"client,omitempty"`
	ClientUUID  string `json:"client_uuid,omitempty"`
	Method      string `json:"method,omitempty"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status,omitempty"`
	Risk        string `json:"risk,omitempty"`
	Message     string `json:"message"`
}

type securityActionRequest struct {
	IP       string `json:"ip"`
	Client   string `json:"client"`
	Reason   string `json:"reason"`
	Duration int    `json:"duration"`
}

func Dashboard(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(dashboardHTML))
}

func ListAttacks(c *gin.Context) {
	limit := parseLimit(c.DefaultQuery("limit", "100"), 1, 500)
	logs, err := querySecurityLogs(limit * 4)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resolver := newClientResolver()
	states := loadIPStates()
	attacks := make([]SecurityAttack, 0, limit)
	seen := make(map[string]struct{}, limit)
	for _, logEntry := range logs {
		attack, ok := attackFromLog(logEntry, resolver, states)
		if !ok {
			continue
		}
		key := attack.ClientUUID + "|" + attack.Client + "|" + attack.SourceIP + "|" + attack.User
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		attacks = append(attacks, attack)
		if len(attacks) >= limit {
			break
		}
	}
	api.RespondSuccess(c, gin.H{"attacks": attacks})
}

func ListEvents(c *gin.Context) {
	limit := parseLimit(c.DefaultQuery("limit", "100"), 1, 500)
	logs, err := querySecurityLogs(limit * 3)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resolver := newClientResolver()
	states := loadIPStates()
	events := make([]SecurityEvent, 0, limit)
	for _, logEntry := range logs {
		if event, ok := eventFromLog(logEntry, resolver, states); ok {
			events = append(events, event)
			if len(events) >= limit {
				break
			}
		}
	}
	api.RespondSuccess(c, gin.H{"events": events})
}

func BanIP(c *gin.Context) {
	req, ok := bindAction(c)
	if !ok {
		return
	}
	if strings.Contains(req.IP, "/") {
		api.RespondError(c, http.StatusBadRequest, "ban only supports a single IP")
		return
	}
	if req.Client != "" {
		if notification, err := sshlogin.GetNotification(req.Client); err == nil && notification.IsIPWhitelisted(req.IP) {
			api.RespondError(c, http.StatusBadRequest, "IP is whitelisted for this client")
			return
		}
	}
	states := loadIPStates()
	key := stateKey(req.Client, req.IP)
	states[key] = IPState{
		Status:    "banned",
		Client:    req.Client,
		IP:        req.IP,
		Reason:    trimSingleLine(req.Reason, 160),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	if err := saveIPStates(states); err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resp := gin.H{"status": "banned", "mode": "panel_mark_only"}
	if req.Client != "" {
		action, err := securityactions.Enqueue(req.Client, req.IP, securityactions.ActionBan, normalizeDuration(req.Duration))
		if err != nil {
			api.RespondError(c, http.StatusInternalServerError, err.Error())
			return
		}
		resp["mode"] = "agent_action_queued"
		resp["action"] = action
		auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard ban ip=%s client=%s action_id=%s mode=agent_action_queued", req.IP, req.Client, action.ID), "warn")
	} else {
		auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard ban ip=%s client=%s mode=panel_mark_only", req.IP, req.Client), "warn")
	}
	api.RespondSuccess(c, resp)
}

func UnbanIP(c *gin.Context) {
	req, ok := bindAction(c)
	if !ok {
		return
	}
	if strings.Contains(req.IP, "/") {
		api.RespondError(c, http.StatusBadRequest, "unban only supports a single IP")
		return
	}
	states := loadIPStates()
	delete(states, stateKey(req.Client, req.IP))
	delete(states, stateKey("", req.IP))
	if err := saveIPStates(states); err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	resp := gin.H{"status": "active", "mode": "panel_mark_only"}
	if req.Client != "" {
		action, err := securityactions.Enqueue(req.Client, req.IP, securityactions.ActionUnban, normalizeDuration(req.Duration))
		if err != nil {
			api.RespondError(c, http.StatusInternalServerError, err.Error())
			return
		}
		resp["mode"] = "agent_action_queued"
		resp["action"] = action
		auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard unban ip=%s client=%s action_id=%s mode=agent_action_queued", req.IP, req.Client, action.ID), "warn")
	} else {
		auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard unban ip=%s client=%s mode=panel_mark_only", req.IP, req.Client), "warn")
	}
	api.RespondSuccess(c, resp)
}

func WhitelistIP(c *gin.Context) {
	req, ok := bindAction(c)
	if !ok {
		return
	}
	if strings.TrimSpace(req.Client) == "" {
		api.RespondError(c, http.StatusBadRequest, "client is required for whitelist")
		return
	}
	notification, err := sshlogin.GetNotification(req.Client)
	if err != nil {
		api.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	entry := strings.TrimSpace(req.IP)
	for _, existing := range notification.IPWhitelist {
		if strings.TrimSpace(existing) == entry {
			auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard whitelist ip=%s client=%s already_exists=true", entry, req.Client), "info")
			api.RespondSuccess(c, gin.H{"status": "whitelisted"})
			return
		}
	}
	notification.IPWhitelist = append(notification.IPWhitelist, entry)
	if err := sshlogin.EditNotifications([]models.SSHLoginNotification{notification}); err != nil {
		api.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if !strings.Contains(entry, "/") {
		if action, err := securityactions.Enqueue(req.Client, entry, securityactions.ActionUnban, normalizeDuration(req.Duration)); err == nil {
			auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard whitelist ip=%s client=%s queued_unban_action=%s", entry, req.Client, action.ID), "warn")
		}
	}
	auditlog.Log(c.ClientIP(), actorUUID(c), fmt.Sprintf("security dashboard whitelist ip=%s client=%s", entry, req.Client), "warn")
	api.RespondSuccess(c, gin.H{"status": "whitelisted"})
}

func bindAction(c *gin.Context) (securityActionRequest, bool) {
	var req securityActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		api.RespondError(c, http.StatusBadRequest, "invalid request body: "+err.Error())
		return req, false
	}
	req.IP = strings.TrimSpace(req.IP)
	req.Client = strings.TrimSpace(req.Client)
	if !validIPOrCIDR(req.IP) {
		api.RespondError(c, http.StatusBadRequest, "invalid IP or CIDR")
		return req, false
	}
	if req.Client != "" {
		if _, err := clients.GetClientByUUID(req.Client); err != nil {
			api.RespondError(c, http.StatusBadRequest, "invalid client")
			return req, false
		}
	}
	return req, true
}

func querySecurityLogs(limit int) ([]models.Log, error) {
	var logs []models.Log
	err := dbcore.GetDBInstance().
		Model(&models.Log{}).
		Where("message LIKE ? OR message LIKE ? OR message LIKE ? OR message LIKE ? OR message LIKE ? OR message LIKE ?",
			"SSH auth guard alert:%",
			"SSH auth guard alert suppressed:%",
			"Event message sent via%: SSH 爆破告警",
			"Event message sent via%: Offline",
			"Event message sent via%: Online",
			"Failed to send event message via%",
		).
		Order("time DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

func attackFromLog(logEntry models.Log, resolver clientResolver, states map[string]IPState) (SecurityAttack, bool) {
	clientName := ""
	clientUUID := ""
	sourceIP := ""
	user := ""
	method := ""
	failedCount := 0

	if match := authGuardAlertNewRE.FindStringSubmatch(logEntry.Message); match != nil {
		clientName = strings.TrimSpace(match[1])
		clientUUID = strings.TrimSpace(match[2])
		sourceIP = strings.TrimSpace(match[3])
		user = strings.TrimSpace(match[4])
		method = strings.TrimSpace(match[5])
		failedCount, _ = strconv.Atoi(strings.TrimSpace(match[6]))
	} else if match := authGuardAlertOldRE.FindStringSubmatch(logEntry.Message); match != nil {
		clientName = strings.TrimSpace(match[1])
		sourceIP = strings.TrimSpace(match[2])
		user = strings.TrimSpace(match[3])
		failedCount, _ = strconv.Atoi(strings.TrimSpace(match[4]))
	} else {
		return SecurityAttack{}, false
	}

	if clientUUID == "" {
		clientUUID = resolver.UUIDByName(clientName)
	}
	if method == "" {
		method = "unknown"
	}
	status := resolveIPStatus(clientUUID, sourceIP, states)
	return SecurityAttack{
		SourceIP:    sourceIP,
		User:        user,
		FailedCount: failedCount,
		Client:      clientName,
		ClientUUID:  clientUUID,
		Method:      method,
		Timestamp:   logEntry.Time.ToTime().Format(time.RFC3339),
		Status:      status,
		Risk:        riskLevel(failedCount, status),
	}, true
}

func eventFromLog(logEntry models.Log, resolver clientResolver, states map[string]IPState) (SecurityEvent, bool) {
	if attack, ok := attackFromLog(logEntry, resolver, states); ok {
		return SecurityEvent{
			ID:          logEntry.ID,
			Type:        "SSHAuthGuardAlert",
			SourceIP:    attack.SourceIP,
			User:        attack.User,
			FailedCount: attack.FailedCount,
			Client:      attack.Client,
			ClientUUID:  attack.ClientUUID,
			Method:      attack.Method,
			Timestamp:   attack.Timestamp,
			Status:      attack.Status,
			Risk:        attack.Risk,
			Message:     logEntry.Message,
		}, true
	}
	if match := authGuardSuppressedRE.FindStringSubmatch(logEntry.Message); match != nil {
		clientName := strings.TrimSpace(match[1])
		clientUUID := strings.TrimSpace(match[2])
		sourceIP := strings.TrimSpace(match[3])
		if clientUUID == "" {
			clientUUID = resolver.UUIDByName(clientName)
		}
		return SecurityEvent{
			ID:         logEntry.ID,
			Type:       "SSHAuthGuardSuppressed",
			SourceIP:   sourceIP,
			Client:     clientName,
			ClientUUID: clientUUID,
			Timestamp:  logEntry.Time.ToTime().Format(time.RFC3339),
			Status:     resolveIPStatus(clientUUID, sourceIP, states),
			Message:    logEntry.Message,
		}, true
	}
	if match := eventSentRE.FindStringSubmatch(logEntry.Message); match != nil {
		eventName := strings.TrimSpace(match[2])
		if eventName == "Offline" || eventName == "Online" {
			return SecurityEvent{
				ID:        logEntry.ID,
				Type:      eventName,
				Timestamp: logEntry.Time.ToTime().Format(time.RFC3339),
				Status:    "active",
				Risk:      eventRisk(eventName),
				Message:   logEntry.Message,
			}, true
		}
	}
	if match := eventFailedRE.FindStringSubmatch(logEntry.Message); match != nil {
		eventName := strings.TrimSpace(match[2])
		if eventName == "SSH 爆破告警" || eventName == "Offline" || eventName == "Online" {
			return SecurityEvent{
				ID:        logEntry.ID,
				Type:      eventName + "SendFailed",
				Timestamp: logEntry.Time.ToTime().Format(time.RFC3339),
				Status:    "active",
				Risk:      "medium",
				Message:   logEntry.Message,
			}, true
		}
	}
	return SecurityEvent{}, false
}

func resolveIPStatus(clientUUID, sourceIP string, states map[string]IPState) string {
	if clientUUID != "" {
		if notification, err := sshlogin.GetNotification(clientUUID); err == nil && notification.IsIPWhitelisted(sourceIP) {
			return "whitelisted"
		}
		if status := matchMarkedState(states, clientUUID, sourceIP); status != "" {
			return status
		}
	}
	if status := matchMarkedState(states, "", sourceIP); status != "" {
		return status
	}
	return "active"
}

func matchMarkedState(states map[string]IPState, clientUUID, sourceIP string) string {
	if state, ok := states[stateKey(clientUUID, sourceIP)]; ok && state.Status != "" {
		return state.Status
	}
	parsed := net.ParseIP(sourceIP)
	if parsed == nil {
		return ""
	}
	for _, state := range states {
		if strings.TrimSpace(state.Client) != strings.TrimSpace(clientUUID) || state.Status == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(state.IP); err == nil && ipNet.Contains(parsed) {
			return state.Status
		}
	}
	return ""
}

func riskLevel(failedCount int, status string) string {
	if status == "whitelisted" {
		return "low"
	}
	if status == "banned" {
		return "high"
	}
	if failedCount >= 20 {
		return "high"
	}
	if failedCount >= 5 {
		return "medium"
	}
	return "low"
}

func eventRisk(eventName string) string {
	switch eventName {
	case "Offline":
		return "high"
	case "Online":
		return "low"
	default:
		return "medium"
	}
}

func validIPOrCIDR(value string) bool {
	if strings.Contains(value, "/") {
		_, _, err := net.ParseCIDR(value)
		return err == nil
	}
	return net.ParseIP(value) != nil
}

func trimSingleLine(value string, maxLen int) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " "))
	if len(value) > maxLen {
		return value[:maxLen]
	}
	return value
}

func loadIPStates() map[string]IPState {
	states, err := config.GetAs[map[string]IPState](securityIPStatesKey, map[string]IPState{})
	if err != nil || states == nil {
		return map[string]IPState{}
	}
	return states
}

func saveIPStates(states map[string]IPState) error {
	return config.Set(securityIPStatesKey, states)
}

func stateKey(clientUUID, sourceIP string) string {
	return strings.TrimSpace(clientUUID) + "|" + strings.TrimSpace(sourceIP)
}

func parseLimit(raw string, min, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return max
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func actorUUID(c *gin.Context) string {
	if uuid, ok := c.Get("uuid"); ok {
		if s, ok := uuid.(string); ok {
			return s
		}
	}
	return ""
}

func normalizeDuration(duration int) int {
	if duration <= 0 {
		return 3600
	}
	if duration < 30 {
		return 30
	}
	if duration > 86400 {
		return 86400
	}
	return duration
}

type clientResolver struct {
	byName map[string]string
}

func newClientResolver() clientResolver {
	list, err := clients.GetAllClientBasicInfo()
	if err != nil {
		return clientResolver{byName: map[string]string{}}
	}
	byName := make(map[string]string, len(list))
	count := make(map[string]int, len(list))
	for _, client := range list {
		count[client.Name]++
	}
	for _, client := range list {
		if count[client.Name] == 1 {
			byName[client.Name] = client.UUID
		}
	}
	return clientResolver{byName: byName}
}

func (r clientResolver) UUIDByName(name string) string {
	return r.byName[strings.TrimSpace(name)]
}

const dashboardHTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH 安全事件控制台</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7fb;--card:#fff;--text:#172033;--muted:#657084;--line:#e7eaf1;--blue:#3478f6;--purple:#6157e8;--green:#1fa463;--yellow:#c88900;--orange:#f08a24;--red:#d83b3b;--shadow:0 8px 26px rgba(20,28,45,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#10131a;--card:#171b24;--text:#edf1f7;--muted:#9ca8ba;--line:#2b3140;--shadow:0 12px 34px rgba(0,0,0,.24)}}
body{margin:0;background:var(--bg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans SC",sans-serif;color:var(--text)}
.wrap{max-width:1280px;margin:0 auto;padding:18px}
.top{display:flex;gap:12px;align-items:center;justify-content:space-between;margin-bottom:14px}
h1{font-size:22px;margin:0}.sub{color:var(--muted);font-size:13px;margin-top:4px}.grid{display:grid;grid-template-columns:1fr;gap:14px}
.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:14px}.metric{background:linear-gradient(180deg,var(--card),rgba(255,255,255,.72));border:1px solid var(--line);border-radius:18px;padding:14px;box-shadow:var(--shadow);position:relative;overflow:hidden}.metric:after{content:"";position:absolute;right:-28px;top:-28px;width:90px;height:90px;border-radius:999px;background:rgba(97,87,232,.07)}.metric .label{color:var(--muted);font-size:13px;font-weight:700}.metric .value{font-size:28px;font-weight:850;margin-top:8px}.metric.red{border-color:rgba(216,59,59,.22)}.metric.red .value{color:var(--red)}.metric.orange .value{color:var(--orange)}.metric.gray .value{color:var(--muted)}.metric.blue .value{color:var(--blue)}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:var(--shadow)}
.card h2{font-size:16px;margin:0 0 12px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
button{border:0;border-radius:10px;background:var(--purple);color:white;padding:8px 11px;font-weight:650;cursor:pointer;transition:transform .15s ease,opacity .15s ease,box-shadow .15s ease}button:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(20,28,45,.12)}
button.secondary{background:#8c96a8}button.danger{background:var(--red)}button.good{background:var(--green)}
input{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:10px;padding:9px 10px;min-width:220px}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:980px}th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left;font-size:13px;vertical-align:middle}th{color:var(--muted);font-weight:650}tbody tr{cursor:pointer;transition:background .15s ease}tbody tr:hover{background:rgba(97,87,232,.055)}tbody tr.row-banned{opacity:.64;background:rgba(101,112,132,.06)}tbody tr.row-high{box-shadow:inset 3px 0 0 var(--red)}
.tag{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:750;white-space:nowrap}.low{background:rgba(31,164,99,.14);color:var(--green)}.medium{background:rgba(240,138,36,.18);color:var(--orange)}.high{background:rgba(216,59,59,.15);color:var(--red);box-shadow:0 0 18px rgba(216,59,59,.18)}
.status-active{background:rgba(52,120,246,.13);color:var(--blue)}.status-banned{background:rgba(216,59,59,.14);color:var(--red)}.status-whitelisted{background:rgba(31,164,99,.14);color:var(--green)}
.intensity-low{background:rgba(31,164,99,.12);color:var(--green)}.intensity-mid{background:rgba(240,138,36,.16);color:var(--orange)}.intensity-high{background:rgba(216,59,59,.14);color:var(--red)}
.actions{display:flex;gap:6px;flex-wrap:wrap}.stream{display:grid;gap:8px;max-height:360px;overflow:auto;padding-right:3px}.stream-item{border:1px solid var(--line);border-radius:13px;padding:10px 12px;background:linear-gradient(90deg,rgba(52,120,246,.08),transparent)}.stream-item.high{border-color:rgba(216,59,59,.28);box-shadow:0 0 18px rgba(216,59,59,.12)}.stream-top{display:flex;justify-content:space-between;gap:8px;align-items:center}.stream-main{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:7px}.pulse{position:relative}.pulse:before{content:"";display:inline-block;width:7px;height:7px;border-radius:99px;background:var(--blue);margin-right:6px;box-shadow:0 0 0 0 rgba(52,120,246,.58);animation:pulse 1.6s infinite}@keyframes pulse{70%{box-shadow:0 0 0 8px rgba(52,120,246,0)}100%{box-shadow:0 0 0 0 rgba(52,120,246,0)}}
.events{display:flex;flex-direction:column;gap:8px}.event{border:1px solid var(--line);border-radius:12px;padding:10px}.event-top{display:flex;justify-content:space-between;gap:8px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.muted{color:var(--muted)}.err{color:var(--red);margin-bottom:10px}
.drawer-mask{position:fixed;inset:0;background:rgba(8,12,20,.42);display:none;z-index:20}.drawer{position:fixed;right:0;top:0;height:100vh;width:min(520px,92vw);background:var(--card);border-left:1px solid var(--line);box-shadow:-18px 0 40px rgba(0,0,0,.22);transform:translateX(102%);transition:transform .22s ease;z-index:21;overflow:auto}.drawer.open{transform:translateX(0)}.drawer-mask.open{display:block}.drawer-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;padding:18px;border-bottom:1px solid var(--line)}.drawer-body{padding:16px;display:grid;gap:14px}.kv{display:grid;grid-template-columns:120px 1fr;gap:8px;font-size:13px}.mini-card{border:1px solid var(--line);border-radius:14px;padding:12px}.timeline{display:grid;gap:8px}.timeline-item{border-left:3px solid var(--blue);padding-left:10px}.chart{width:100%;height:120px}.close{background:#8c96a8}.nowrap{white-space:nowrap}
@media (max-width:900px){.overview{grid-template-columns:repeat(2,minmax(0,1fr))}.stream-top{align-items:flex-start;flex-direction:column}}
@media (max-width:720px){.wrap{padding:12px}.top{align-items:flex-start;flex-direction:column}h1{font-size:20px}.card{padding:12px}.overview{grid-template-columns:1fr}input{width:100%;min-width:0}.toolbar button{flex:1}.event-top{flex-direction:column}.kv{grid-template-columns:92px 1fr}.metric .value{font-size:24px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div><h1>🛡️ SSH 安全事件控制台</h1><div class="sub">展示 SSH Auth Guard、上下线事件；封禁会投递固定 ban/unban 动作给对应 agent，面板不执行系统命令。</div></div>
    <div class="toolbar"><button onclick="reloadAll()">刷新</button><button class="secondary" onclick="location.href='/admin'">返回面板</button></div>
  </div>
  <div id="error" class="err"></div>
  <section class="overview" aria-label="安全概览">
    <div class="metric red"><div class="label">🔴 高风险 IP数量</div><div id="metric-high" class="value">--</div></div>
    <div class="metric blue"><div class="label">🟠 正在攻击 IP</div><div id="metric-active" class="value">--</div></div>
    <div class="metric gray"><div class="label">🚫 已封禁 IP数量</div><div id="metric-banned" class="value">--</div></div>
    <div class="metric orange"><div class="label">📊 今日攻击次数</div><div id="metric-today" class="value">--</div></div>
  </section>
  <div class="grid">
    <section class="card">
      <h2>最近攻击流</h2>
      <div id="stream" class="stream"><div class="muted">加载中...</div></div>
    </section>
    <section class="card">
      <h2>IP 攻击列表</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>来源 IP</th><th>目标用户</th><th>失败次数</th><th>攻击强度</th><th>节点</th><th>认证方式</th><th>时间</th><th>风险</th><th>状态</th><th>操作</th></tr></thead>
          <tbody id="attacks"><tr><td colspan="10" class="muted">加载中...</td></tr></tbody>
        </table>
      </div>
    </section>
    <section class="card">
      <h2>实时事件流</h2>
      <div id="events" class="events"><div class="muted">加载中...</div></div>
    </section>
  </div>
</div>
<div id="drawerMask" class="drawer-mask" onclick="closeDrawer()"></div>
<aside id="drawer" class="drawer" aria-label="IP 详情">
  <div class="drawer-head">
    <div><h2 id="drawerTitle" style="margin:0;font-size:18px">IP 详情</h2><div id="drawerSub" class="muted"></div></div>
    <button class="close" onclick="closeDrawer()">关闭</button>
  </div>
  <div id="drawerBody" class="drawer-body"></div>
</aside>
<script>
const statusText = {active:'活跃', banned:'已标记封禁', whitelisted:'白名单'};
const riskText = {low:'低', medium:'中', high:'高'};
const eventTypeText = {
  SSHAuthGuardAlert:'SSH 爆破告警',
  SSHAuthGuardSuppressed:'SSH 爆破降噪',
  Offline:'节点离线',
  Online:'节点恢复',
  'SSH 爆破告警SendFailed':'SSH 爆破告警发送失败',
  OfflineSendFailed:'离线通知发送失败',
  OnlineSendFailed:'恢复通知发送失败',
};
let attackRows = [];
let eventRows = [];
function esc(s){return String(s ?? '').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
async function apiFetch(url, opts={}){
  const res = await fetch(url, {credentials:'same-origin', headers:{'Content-Type':'application/json'}, ...opts});
  const data = await res.json().catch(()=>({status:'error', message:'响应不是 JSON'}));
  if(!res.ok || data.status === 'error') throw new Error(data.message || res.statusText);
  return data.data || {};
}
function toTime(s){const t = Date.parse(s || ''); return Number.isFinite(t) ? t : 0;}
function riskScore(a){
  if((a.status || '') === 'whitelisted') return 10;
  if((a.status || '') === 'banned') return 70;
  const base = a.risk === 'high' ? 90 : (a.risk === 'medium' ? 62 : 28);
  return Math.min(100, base + Math.min(15, Number(a.failed_count || 0)));
}
function riskLabel(a){
  const label = riskText[a.risk] || a.risk || '未知';
  return a.risk === 'high' ? '🔥 '+label : label;
}
function intensity(a){
  const n = Number(a.failed_count || 0);
  if(n >= 20) return {cls:'intensity-high', text:'猛烈'};
  if(n >= 10) return {cls:'intensity-high', text:'较强'};
  if(n >= 5) return {cls:'intensity-mid', text:'持续'};
  return {cls:'intensity-low', text:'轻微'};
}
function sortedAttacks(rows){
  return [...rows].sort((a,b) => riskScore(b)-riskScore(a) || Number(b.failed_count||0)-Number(a.failed_count||0) || toTime(b.timestamp)-toTime(a.timestamp));
}
function isToday(ts){
  const d = new Date(ts || '');
  if(Number.isNaN(d.getTime())) return false;
  const now = new Date();
  return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
}
function updateOverview(rows){
  const unique = new Map();
  rows.forEach(a => unique.set((a.client_uuid || a.client || '')+'|'+a.source_ip, a));
  const list = [...unique.values()];
  document.getElementById('metric-high').textContent = list.filter(a => riskScore(a) >= 80).length;
  document.getElementById('metric-active').textContent = list.filter(a => a.status === 'active').length;
  document.getElementById('metric-banned').textContent = list.filter(a => a.status === 'banned').length;
  document.getElementById('metric-today').textContent = rows.filter(a => isToday(a.timestamp)).reduce((n,a)=>n+Number(a.failed_count||0),0);
}
async function reloadAttacks(){
  const tbody = document.getElementById('attacks');
  const data = await apiFetch('/api/security/attacks?limit=120');
  attackRows = sortedAttacks(data.attacks || []);
  updateOverview(attackRows);
  renderStream();
  tbody.innerHTML = attackRows.length ? attackRows.map(a => {
    const inten = intensity(a);
    const rowClass = (a.status === 'banned' ? 'row-banned ' : '') + (a.risk === 'high' ? 'row-high' : '');
    return '<tr class="'+esc(rowClass)+'" onclick='+"'"+'openDrawer('+JSON.stringify(a.source_ip)+', '+JSON.stringify(a.client_uuid || a.client || '')+')'+"'"+'>'+
      '<td class="mono">'+esc(a.source_ip)+'</td>'+
      '<td>'+esc(a.user)+'</td>'+
      '<td>'+esc(a.failed_count)+'</td>'+
      '<td><span class="tag '+inten.cls+'">'+esc(inten.text)+'</span></td>'+
      '<td>'+esc(a.client)+'</td>'+
      '<td>'+esc(a.method)+'</td>'+
      '<td class="mono">'+esc(a.timestamp)+'</td>'+
      '<td><span class="tag '+esc(a.risk)+'">'+esc(riskLabel(a))+'</span></td>'+
      '<td><span class="tag status-'+esc(a.status)+'">'+esc(statusText[a.status]||a.status)+'</span></td>'+
      '<td><div class="actions">'+
        '<button class="danger" title="立即封禁该IP" onclick='+"'"+'event.stopPropagation();act("ban", '+JSON.stringify(a.source_ip)+', '+JSON.stringify(a.client_uuid)+')'+"'"+'>🚫 Ban IP</button>'+
        '<button class="secondary" title="解除面板封禁标记" onclick='+"'"+'event.stopPropagation();act("unban", '+JSON.stringify(a.source_ip)+', '+JSON.stringify(a.client_uuid)+')'+"'"+'>🔓 Unban</button>'+
        '<button class="good" title="加入白名单，跳过检测" onclick='+"'"+'event.stopPropagation();act("whitelist", '+JSON.stringify(a.source_ip)+', '+JSON.stringify(a.client_uuid)+')'+"'"+'>⭐ Whitelist</button>'+
      '</div></td>'+
    '</tr>';
  }).join('') : '<tr><td colspan="10" class="muted">暂无 SSH 攻击事件</td></tr>';
}
async function reloadEvents(){
  const box = document.getElementById('events');
  const data = await apiFetch('/api/security/events?limit=80');
  eventRows = data.events || [];
  renderStream();
  box.innerHTML = eventRows.length ? eventRows.map(e =>
    '<div class="event">'+
      '<div class="event-top"><strong>'+esc(eventTypeText[e.type]||e.type)+'</strong><span class="mono muted">'+esc(e.timestamp)+'</span></div>'+
      '<div>'+(e.client ? '节点：'+esc(e.client)+' · ' : '')+(e.source_ip ? '来源 IP：<span class="mono">'+esc(e.source_ip)+'</span> · ' : '')+(e.risk ? '<span class="tag '+esc(e.risk)+'">'+esc(riskText[e.risk]||e.risk)+'</span>' : '')+'</div>'+
      '<div class="muted">'+esc(e.message)+'</div>'+
    '</div>').join('') : '<div class="muted">暂无事件</div>';
}
function renderStream(){
  const box = document.getElementById('stream');
  if(!box) return;
  let rows = eventRows.filter(e => e.type === 'SSHAuthGuardAlert');
  if(!rows.length) rows = attackRows;
  rows = [...rows].sort((a,b)=>toTime(b.timestamp)-toTime(a.timestamp)).slice(0,18);
  box.innerHTML = rows.length ? rows.map(e => {
    const st = e.status || 'active';
    const high = (e.risk === 'high' || riskScore(e) >= 80) ? ' high' : '';
    return '<div class="stream-item'+high+'" onclick='+"'"+'openDrawer('+JSON.stringify(e.source_ip)+', '+JSON.stringify(e.client_uuid || e.client || '')+')'+"'"+'>'+
      '<div class="stream-top"><strong class="mono">'+esc(e.timestamp)+'</strong><span class="tag status-'+esc(st)+' '+(st === 'active' ? 'pulse' : '')+'">'+esc(statusText[st]||st)+'</span></div>'+
      '<div class="stream-main">'+
        '<span class="mono">'+esc(e.source_ip)+'</span>'+
        '<span>用户：'+esc(e.user || '-')+'</span>'+
        '<span>方式：'+esc(e.method || '-')+'</span>'+
        '<span>失败：<strong>'+esc(e.failed_count || 0)+'</strong></span>'+
        (e.risk ? '<span class="tag '+esc(e.risk)+'">'+esc(riskLabel(e))+'</span>' : '')+
      '</div></div>';
  }).join('') : '<div class="muted">暂无攻击流</div>';
}
async function act(action, ip, client){
  if(action === 'whitelist' && !client){ alert('旧日志无法定位唯一 client，不能自动加入白名单'); return; }
  const actionText = {ban:'标记封禁', unban:'解除标记', whitelist:'加入白名单'}[action] || action;
  if(!confirm(actionText+' '+ip+' ?')) return;
  await apiFetch('/api/security/'+action, {method:'POST', body:JSON.stringify({ip, client})});
  await reloadAll();
}
function openDrawer(ip, clientKey){
  const item = attackRows.find(a => a.source_ip === ip && ((a.client_uuid || a.client || '') === clientKey)) || attackRows.find(a => a.source_ip === ip);
  if(!item) return;
  const relatedAttacks = attackRows.filter(a => a.source_ip === ip && (!item.client_uuid || a.client_uuid === item.client_uuid || a.client === item.client));
  const relatedEvents = eventRows.filter(e => e.source_ip === ip && (!item.client_uuid || e.client_uuid === item.client_uuid || e.client === item.client)).sort((a,b)=>toTime(b.timestamp)-toTime(a.timestamp));
  const users = [...new Set(relatedAttacks.flatMap(a => String(a.user || '').split(',').map(s=>s.trim()).filter(Boolean)).concat(relatedEvents.flatMap(e => String(e.user || '').split(',').map(s=>s.trim()).filter(Boolean))))];
  const points = relatedEvents.filter(e => e.failed_count).slice(0,12).reverse();
  const scores = points.length ? points.map(e => Math.min(100, Number(e.failed_count || 0) * 10)) : [riskScore(item)];
  document.getElementById('drawerTitle').textContent = item.source_ip;
  document.getElementById('drawerSub').textContent = item.client || '未知节点';
  document.getElementById('drawerBody').innerHTML =
    '<div class="mini-card"><h3 style="margin-top:0">IP 基本信息</h3>'+
      kv('来源 IP', '<span class="mono">'+esc(item.source_ip)+'</span>')+
      kv('节点', esc(item.client || '-'))+
      kv('认证方式', esc(item.method || '-'))+
      kv('失败次数', esc(item.failed_count || 0))+
      kv('风险等级', '<span class="tag '+esc(item.risk)+'">'+esc(riskLabel(item))+'</span>')+
      kv('封禁状态', '<span class="tag status-'+esc(item.status)+'">'+esc(statusText[item.status]||item.status)+'</span>')+
      kv('白名单状态', item.status === 'whitelisted' ? '已加入白名单' : '未命中白名单')+
    '</div>'+
    '<div class="mini-card"><h3 style="margin-top:0">用户尝试列表</h3><div>'+esc(users.join(', ') || '-')+'</div></div>'+
    '<div class="mini-card"><h3 style="margin-top:0">风险评分变化曲线</h3>'+sparkline(scores)+'</div>'+
    '<div class="mini-card"><h3 style="margin-top:0">攻击时间线</h3><div class="timeline">'+
      (relatedEvents.length ? relatedEvents.slice(0,12).map(e => '<div class="timeline-item"><div><strong>'+esc(eventTypeText[e.type]||e.type)+'</strong> <span class="mono muted">'+esc(e.timestamp)+'</span></div><div class="muted">'+esc(e.user || '-')+' · '+esc(e.method || '-')+' · 失败 '+esc(e.failed_count || 0)+'</div></div>').join('') : '<div class="muted">暂无更细事件</div>')+
    '</div></div>';
  document.getElementById('drawerMask').classList.add('open');
  document.getElementById('drawer').classList.add('open');
}
function closeDrawer(){
  document.getElementById('drawerMask').classList.remove('open');
  document.getElementById('drawer').classList.remove('open');
}
function kv(k,v){return '<div class="kv"><strong>'+esc(k)+'</strong><div>'+v+'</div></div>'}
function sparkline(values){
  const max = Math.max(100, ...values);
  const step = values.length > 1 ? 300/(values.length-1) : 300;
  const pts = values.map((v,i)=> (10+i*step)+','+(105-(Number(v||0)/max)*90)).join(' ');
  return '<svg class="chart" viewBox="0 0 320 120" role="img" aria-label="风险评分变化曲线"><polyline points="'+esc(pts)+'" fill="none" stroke="#d83b3b" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><line x1="10" y1="105" x2="310" y2="105" stroke="currentColor" opacity=".14"/><line x1="10" y1="15" x2="10" y2="105" stroke="currentColor" opacity=".14"/></svg>';
}
async function reloadAll(){
  document.getElementById('error').textContent='';
  try{ await Promise.all([reloadAttacks(), reloadEvents()]); }
  catch(e){ document.getElementById('error').textContent=e.message; }
}
reloadAll();
setInterval(reloadAll, 5000);
</script>
</body>
</html>`
