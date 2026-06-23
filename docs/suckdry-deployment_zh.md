# Komari 自用安全版部署教程

本文面向第一次部署的用户，按“先跑起来，再逐步开启通知和安全功能”的顺序说明。示例使用 Docker 部署面板，Agent 使用 `suckdrygod/tcpping` 的 TCP-safe 版本。

## 版本说明

| 组件 | 推荐版本 | 说明 |
| --- | --- | --- |
| Komari 面板 | `ghcr.io/suckdrygod/komari:1.2.5-tg.12` | 包含 Telegram 菜单、流量统计、重置日提醒、SSH 登录通知、SSH Auth Guard 接收端 |
| 安全 Agent | `v1.2.13-safe.9` | 禁用自动更新，限制 TCPing 白名单，支持流量重置日和 SSH Auth Guard |

> 如果你只更新面板，不更新各台 VPS 上的 Agent，新功能不会在旧 Agent 上生效。面板只需要部署一次；每台被监控的 VPS 都需要安装或升级 Agent。

## 功能概览

- Telegram 机器人菜单：按钮式查询今日/昨日/周期/累计/剩余流量。
- 每台机器流量重置日：Agent 上报 `--month-rotate`，面板按机器时区判断。
- 重置日自动提醒：到重置日当天自动推送一张流量卡片。
- SSH 登录成功通知：Agent 只读 SSH 日志，上报成功登录事件。
- SSH Auth Guard：检测 SSH 登录失败爆破，聚合后通知，不自动封禁。
- TCP-safe Agent：保留 TCPing，但只允许访问白名单域名和端口，降低远控风险。

## 1. 准备工作

一台用于部署面板的服务器需要：

- Docker
- 一个可访问面板的域名，或直接使用服务器 IP
- 一个用于 Agent 连接的面板入口，例如 `https://agent.example.com`
- 一个 Telegram Bot Token 和 Chat ID（可选，但推荐）

如果使用 Cloudflare 或反向代理，请确认 WebSocket 可以正常转发。

## 2. 部署面板

创建数据目录：

```bash
mkdir -p /opt/komari/data
```

启动容器：

```bash
docker run -d \
  --name komari \
  --restart unless-stopped \
  -p 127.0.0.1:25774:25774 \
  -v /opt/komari/data:/app/data \
  ghcr.io/suckdrygod/komari:1.2.5-tg.12
```

查看初始账号密码：

```bash
docker logs komari
```

浏览器访问你的面板域名或：

```text
http://服务器IP:25774
```

如果面板放在反向代理后面，建议只把 `25774` 绑定到 `127.0.0.1`，由 Nginx / Caddy / Cloudflare Tunnel 对外提供 HTTPS。

## 3. 配置 Telegram 通知

进入面板：

```text
设置 → 通知 → 通知渠道：telegram
```

填写：

| 字段 | 说明 |
| --- | --- |
| `Telegram Bot Token` | BotFather 创建机器人的 Token |
| `Chat ID` | 私聊或群组的数字 ID |
| `请求端点` | 默认 `https://api.telegram.org/bot` |
| `command_menu_enabled` | 开启后显示 Telegram 蓝色菜单按钮 |
| `command_allowed_users` | 群组使用时建议填写允许操作的 Telegram 数字用户 ID |
| `command_timezone` | 中国用户建议 `Asia/Shanghai` |

保存后点击“发送测试消息”。如果测试消息可以收到，后续离线、恢复、流量、SSH 登录和 SSH Auth Guard 都会复用这套通知渠道。

## 4. 新机器安装 Agent

在面板中添加节点后，会得到该节点的 Token。把下面命令里的 `YOUR_NODE_TOKEN` 换成面板生成的 Token。

基础安全安装：

```bash
curl -fsSL https://raw.githubusercontent.com/suckdrygod/tcpping/main/install.sh | sudo bash -s -- \
  -e https://agent.example.com \
  -t YOUR_NODE_TOKEN
```

如果这台机器有月流量重置日，例如每月 15 日重置：

```bash
curl -fsSL https://raw.githubusercontent.com/suckdrygod/tcpping/main/install.sh | sudo bash -s -- \
  -e https://agent.example.com \
  -t YOUR_NODE_TOKEN \
  --month-rotate 15
```

如果要开启 SSH Auth Guard：

```bash
curl -fsSL https://raw.githubusercontent.com/suckdrygod/tcpping/main/install.sh | sudo bash -s -- \
  -e https://agent.example.com \
  -t YOUR_NODE_TOKEN \
  --month-rotate 15 \
  --ssh-auth-guard
```

> `https://agent.example.com` 请替换成你的面板 Agent 入口。你当前如果使用子域名，例如 `https://agent.suckdry.com`，继续使用该子域名即可。

## 5. 升级已有 Agent

已有机器升级到最新 TCP-safe Agent：

```bash
curl -fsSL https://raw.githubusercontent.com/suckdrygod/tcpping/main/upgrade.sh | sudo bash
sudo systemctl restart komari-agent
```

如果机器已经是 root 用户：

```bash
curl -fsSL https://raw.githubusercontent.com/suckdrygod/tcpping/main/upgrade.sh | bash
systemctl restart komari-agent
```

开启 SSH Auth Guard 的 systemd 覆盖配置：

```bash
sudo bash -s <<'SCRIPT'
set -e

mkdir -p /etc/systemd/system/komari-agent.service.d

exec_line="$(systemctl cat komari-agent | awk '/^ExecStart=/{if ($0!="ExecStart=") line=$0} END{print line}')"
[ -n "$exec_line" ] || { echo "未找到 komari-agent ExecStart"; exit 1; }

case "$exec_line" in
  *--ssh-auth-guard*) ;;
  *) exec_line="$exec_line --ssh-auth-guard" ;;
esac

{
  echo "[Service]"
  echo "ExecStart="
  echo "$exec_line"
} > /etc/systemd/system/komari-agent.service.d/20-ssh-auth-guard.conf

systemctl daemon-reload
systemctl restart komari-agent
SCRIPT
```

检查是否生效：

```bash
systemctl is-active komari-agent
systemctl cat komari-agent | grep -- '--ssh-auth-guard'
journalctl -u komari-agent -n 80 --no-pager | grep -Ei 'Komari Agent|SSH auth guard|WebSocket connected'
```

看到类似下面日志即代表开启：

```text
Komari Agent v1.2.13-safe.9
SSH auth guard watching systemd journal
WebSocket connected using v2 protocol
```

## 6. SSH Auth Guard 默认规则

默认参数：

```bash
--ssh-auth-threshold 5
--ssh-auth-window 60
--ssh-auth-cooldown 600
--ssh-auth-root-only false
```

含义：

- 60 秒内，同一来源 IP + 同一目标用户失败 5 次，触发 1 次告警。
- 同一来源 IP + 用户触发后，10 分钟内不会重复刷屏。
- 默认检测 root 和普通用户，不只检测 root。

SSH Auth Guard 只做检测和告警：

- 不调用 `iptables`
- 不调用 `nftables`
- 不调用 `fail2ban`
- 不调用 `sshguard`
- 不执行任何封禁命令
- 不新增远程命令能力

面板会复用“SSH 登录通知”的配置：

- 该节点未启用 SSH 登录通知：不推送
- 来源 IP 命中白名单：不推送
- 否则使用当前 Telegram / Email 通知渠道发送告警

## 7. 流量统计和重置日

### 面板显示的流量

面板主要使用 Agent 上报的网卡流量计数。新版 Agent 支持 `--month-rotate`，可以告诉面板每台机器的月流量重置日。

### vnStat 的作用

如果机器安装了 `vnstat`，它适合作为独立参考口径。vnStat 会维护自己的数据库，重启机器不会自动清零。面板不会直接替代 vnStat，两者统计口径可能有少量差异，属于正常现象。

### 没有设置重置日会怎样

未设置 `--month-rotate` 的机器会按累计计数持续叠加。建议给有月流量套餐的机器设置真实重置日，方便 Telegram 查询“剩余总流量”和重置提醒。

## 8. Telegram 常用命令

| 命令 | 说明 |
| --- | --- |
| `/start` | 打开主菜单 |
| `/nodes` | 机器列表 |
| `/today` | 今日流量 |
| `/yesterday` | 昨日流量 |
| `/cycle` | 当前周期流量 |
| `/total` | 单台机器累计总流量 |
| `/alltotal` | 所有机器累计总流量 |
| `/remaining` | 剩余总流量 |
| `/reset` | 查询重置日 |
| `/status` | 运行状态 |
| `/report` | 完整报告 |

如果按钮不显示，先确认：

1. Telegram 通知渠道已保存。
2. `command_menu_enabled` 已开启。
3. Bot 没有被其他程序同时 `getUpdates` 轮询。
4. 群组使用时，`command_allowed_users` 已填写你的 Telegram 数字 ID。

## 9. 常见问题

### 面板和 Agent 都要升级吗？

是。面板只需要升级一次；每台 VPS 如果要使用 SSH Auth Guard、重置日上报和新版流量能力，都需要升级 Agent。

### 子域名部署会影响 Agent 吗？

不影响。Agent 只需要能访问你的面板入口即可，例如：

```bash
-e https://agent.example.com
```

确保反向代理支持 WebSocket，并且该地址最终能到达 Komari 面板。

### 国内机器下载 GitHub 很慢怎么办？

可以在本地先下载 release 二进制，然后用 SSH 工具上传到服务器替换 `/opt/komari/agent`。替换前建议备份旧文件：

```bash
cp -a /opt/komari/agent /opt/komari/agent.backup-$(date +%Y%m%d%H%M%S)
install -m 0755 ./komari-agent-linux-amd64 /opt/komari/agent
systemctl restart komari-agent
```

### 怎么确认没有远控风险扩大？

TCP-safe Agent 默认禁用自动更新，并限制 TCPing 白名单。SSH Auth Guard 只读本机 SSH 日志并上报聚合告警，不上传密码、密钥、完整原始日志，也不会执行封禁或远程命令。

## 10. 升级面板

Docker 用户：

```bash
docker pull ghcr.io/suckdrygod/komari:1.2.5-tg.12
docker stop komari
docker rm komari
docker run -d \
  --name komari \
  --restart unless-stopped \
  -p 127.0.0.1:25774:25774 \
  -v /opt/komari/data:/app/data \
  ghcr.io/suckdrygod/komari:1.2.5-tg.12
```

确认运行镜像：

```bash
docker inspect komari --format '{{.Config.Image}}'
docker logs --tail 50 komari
```

## 11. 推荐验收步骤

部署完成后建议依次检查：

```bash
# Agent 在线
systemctl is-active komari-agent

# Agent 版本和 Auth Guard
journalctl -u komari-agent -n 80 --no-pager | grep -Ei 'Komari Agent|SSH auth guard|WebSocket connected'

# 面板容器
docker inspect komari --format '{{.Config.Image}}'
docker logs --tail 80 komari

# Telegram
在面板通知页发送测试消息
在 Telegram 发送 /start
```

全部正常后，再逐台开启重置日、剩余流量和 SSH 白名单。
