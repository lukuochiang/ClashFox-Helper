# ClashFox Privileged Helper (custom implementation)

这个仓库提供了一个自定义的 macOS Privileged Helper，用于让桌面应用安全地执行需要 root 权限的网络操作（代理、DNS、TUN 前置能力）。

## 对 `clashfox-helper` 的代码分析（简述）

从仓库结构和入口实现可以看出，它的核心是：

1. `helper` 常驻运行于系统级权限（root）。
2. 对外暴露本地 API（用于 GUI 进程发起控制请求）。
3. 核心能力通过调用系统命令实现（例如 `networksetup`），从而切换代理或网络相关设置。
4. 服务部署依赖 launchd（系统服务模型）。

本仓库沿用这一设计思想，并加入了生产向加固：

1. 仅监听本地 Unix Socket（`/var/run/com.clashfox.helper.sock`）。
2. 所有 API 必须携带 `X-Helper-Token`。
3. 调用方约束：读取 Unix Socket peer 的 `uid/pid/path`，仅允许策略文件中的调用方。
4. 命令白名单：仅允许 `networksetup` / `sysctl` / `pfctl` 的受限子命令与参数。
5. 参数收紧：代理地址仅允许 loopback（`127.0.0.1`/`::1`/`localhost`），DNS 数量限制 1..3。
6. 失败回滚：修改代理/DNS 前先读当前值，执行失败自动恢复。
7. 幂等语义：目标状态已满足时返回 `ok=true, code=NOOP`，不重复执行系统命令。
8. 异常自愈：周期性比对并恢复 `state.json` 的目标状态。
9. 基线恢复：首次变更前保存 `baseline.json`，支持一键恢复。
10. 并发互斥：同一 network service 串行执行，避免竞态覆盖。
11. 防刷限速：按调用方做窗口限流（过载返回 `RATE_LIMITED`）。
12. 失败熔断：连续失败触发临时封禁（返回 `CIRCUIT_OPEN`）。
13. 漂移告警：自愈前记录 `expected/current` 差异到审计日志。
14. 安装原子升级：失败自动回滚到旧二进制与旧 plist。
15. 卸载安全：卸载前自动尝试恢复 baseline，避免残留代理/DNS。
16. 审计日志：记录调用方身份、动作、结果、状态快照。

## 功能

- `POST /v1/proxy/global`: 开启系统 HTTP/HTTPS 代理
- `POST /v1/proxy/off`: 关闭系统 HTTP/HTTPS 代理
- `POST /v1/dns/set`: 设置 DNS
- `POST /v1/tun/enable`: 开启 TUN 前置能力（IP forwarding / pf）
- `POST /v1/tun/disable`: 关闭 TUN 前置能力
- `POST /v1/state/restore`: 按 baseline 恢复（支持全量/单服务）
- `POST /v1/core/start`: 启动 `mihomo` 内核（固定路径+固定参数模板）
- `POST /v1/core/stop`: 停止 `mihomo` 内核
- `POST /v1/core/restart`: 重启 `mihomo` 内核（失败自动尝试回滚重启）
- `GET /v1/core/status`: 查询 `mihomo` 运行状态
- `POST /v1/core/reload`: 向运行中的 `mihomo` 发送 `SIGHUP` 触发重载
- `POST /v1/core/config/validate`: 校验固定配置文件（`mihomo -t`）
- `POST /v1/core/switch`: 从受控更新目录切换内核二进制（原子替换+失败回滚）
- `GET /v1/version`: 获取 helper 版本信息（version/commit/buildTime/launchedAt）
- `GET /health`: 健康检查

## 构建

```bash
bash scripts/build-helper.sh ./build/com.clashfox.helper
```

版本来源：仓库根目录 [VERSION](/Users/workstation/os-code/ClashFox-Helper/VERSION)。

## 安装为系统服务（需要管理员权限）

```bash
sudo bash scripts/install-helper.sh ./build/com.clashfox.helper
```

安装后：

- 二进制: `/Library/PrivilegedHelperTools/com.clashfox.helper`
- 启动项: `/Library/LaunchDaemons/com.clashfox.helper.plist`
- Socket: `/var/run/com.clashfox.helper.sock`
- Token: `/Library/Application Support/ClashFox/helper/token`
- 调用策略: `/Library/Application Support/ClashFox/helper/policy.json`
- 期望状态: `/Library/Application Support/ClashFox/helper/state.json`
- 基线状态: `/Library/Application Support/ClashFox/helper/baseline.json`
- 版本信息: `/Library/Application Support/ClashFox/helper/version.json`
- 版本历史: `/Library/Application Support/ClashFox/helper/version-history.log`
- 旧版本备份: `/Library/Application Support/ClashFox/helper/releases/`
- mihomo pidfile: `/Library/Application Support/ClashFox/helper/mihomo.pid`
- mihomo lockfile: `/Library/Application Support/ClashFox/helper/mihomo.lock`
- mihomo log: `/var/log/clashfox-mihomo.log`
- mihomo 受控二进制: `/Library/Application Support/ClashFox/core/mihomo`
- mihomo 更新目录（面板检测下载）: `/Library/Application Support/ClashFox/core/cfox-backup/`
- mihomo 备份目录（GUI安装备份）: `/Library/Application Support/ClashFox/core/cfox-backup/`
- 运行日志: `/var/log/clashfox-helper.log`
- 审计日志: `/var/log/clashfox-helper-audit.log`

## 卸载

```bash
sudo bash scripts/uninstall-helper.sh
```

说明：卸载脚本会在删除服务前尝试调用 `/v1/state/restore`，并把旧二进制/plist 备份到 `uninstall-backup-*` 目录。

## 调用示例

```bash
TOKEN="$(cat '/Library/Application Support/ClashFox/helper/token')"

curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://localhost/v1/proxy/global \
  -d '{"service":"Wi-Fi","host":"127.0.0.1","port":7890}'
```

恢复基线状态（全量）：

```bash
curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://localhost/v1/state/restore
```

恢复基线状态（单服务）：

```bash
curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://localhost/v1/state/restore \
  -d '{"service":"Wi-Fi"}'
```

兼容性冒烟测试（含 macOS 12 解析样例）：

```bash
bash scripts/compat-smoke.sh
```

常见错误码：

- `RATE_LIMITED`: 调用过于频繁
- `CIRCUIT_OPEN`: 调用方在短时间内失败过多，被临时封禁
- `TXN_APPLY_FAILED`: 事务执行失败，已尝试回滚
- `NOOP`: 当前状态已满足目标，未重复执行

查询版本：

```bash
curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -X GET http://localhost/v1/version
```

操作 mihomo 内核：

```bash
curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -X POST http://localhost/v1/core/start

curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -X GET http://localhost/v1/core/status

curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -X POST http://localhost/v1/core/reload

curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -X POST http://localhost/v1/core/config/validate

curl --unix-socket /var/run/com.clashfox.helper.sock \
  -H "X-Helper-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST http://localhost/v1/core/switch \
  -d '{"candidate":"mihomo-v1.19.3"}'
```

约束说明（已内置）：

- 只允许白名单二进制路径：`/usr/local/bin/mihomo`、`/opt/homebrew/bin/mihomo`、`/Applications/ClashFox.app/Contents/Resources/mihomo`
- 固定参数模板：`-d /Library/Application Support/ClashFox/core -f /Library/Application Support/ClashFox/core/config.yaml`
- `pidfile + lockfile` 防止重复实例
- `pidfile` 为结构化记录（pid+binary+startedAt），并校验 PID 对应二进制路径，降低 PID 复用误操作风险
- 退出码写入审计日志（`act=core_exit`）
- `switch` 仅允许 `cfox-backup/` 目录下的文件名（禁止路径穿越）
- `switch` 需要 SHA256 完整性校验（请求体 `sha256` 或同名 `.sha256` 文件）

## 生产建议

1. 若要对接 Apple 官方授权安装链路，建议使用 `SMJobBless` + 签名校验（Team ID / Requirement）。
2. 若 GUI 和 helper 分离，建议改为 NSXPC 并在 helper 侧加 `audit token` 校验调用方签名。
3. 按实际 App 安装位置维护 `policy.json` 中的 `allowedClientPathPrefixes`，避免误拦截。
4. 版本兼容测试建议包含 macOS 12/13/14/15（尤其 `networksetup` 输出和 `pfctl` 状态解析差异）。
