# ClashFox Helper API Demo (Minimal Scope)

helper 仅负责：

- `mihomo` 启动 / 停止 / 重启 / 状态
- 系统代理开启 / 关闭

## 0. 准备

```bash
SOCK="/var/run/com.clashfox.helper.sock"
TOKEN="$(cat '/Library/Application Support/ClashFox/helper/token')"
```

## 1. 健康与版本

```bash
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X GET "http://localhost/health"
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X GET "http://localhost/version"
```

## 2. 系统代理

开启代理（HTTP/HTTPS/SOCKS）：

```bash
curl --unix-socket "$SOCK" \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost/v1/proxy/enable" \
  -d '{"host":"127.0.0.1","port":7890,"socks-port":7891}'

# 可选：带状态快照返回（避免再调用 /v1/proxy/status）
curl --unix-socket "$SOCK" \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost/v1/proxy/enable?withStatus=1" \
  -d '{"host":"127.0.0.1","port":7890,"socks-port":7891}'
```

关闭代理：

```bash
curl --unix-socket "$SOCK" \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost/v1/proxy/disable" \
  -d '{}'

# 可选：NOOP/成功都可返回状态快照
curl --unix-socket "$SOCK" \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST "http://localhost/v1/proxy/disable?withStatus=1" \
  -d '{}'
```

查询代理状态（`service` 可选）：

```bash
curl --unix-socket "$SOCK" \
  -H "X-Helper-Token: ${TOKEN}" \
  -X GET "http://localhost/v1/proxy/status?service=Wi-Fi"
```

## 3. mihomo 控制

启动：

```bash
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X POST "http://localhost/v1/core/start"
```

状态：

```bash
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X GET "http://localhost/v1/core/status"
```

重启：

```bash
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X POST "http://localhost/v1/core/restart"
```

停止：

```bash
curl --unix-socket "$SOCK" -H "X-Helper-Token: ${TOKEN}" -X POST "http://localhost/v1/core/stop"
```
