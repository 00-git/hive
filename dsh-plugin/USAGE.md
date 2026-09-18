# hive 使用手册（第一步 MVP）

> 现状：一台机器同时扮演「服务器」和「PC」进行演示。真实场景中，
> 服务器与各 PC 分属不同电脑，网络互通即可（跨网组网 = 第二步之后的 OpenP2P）。

## 角色与进程

| 角色 | 跑什么 | 在哪台机器 |
|---|---|---|
| **服务器（Gateway）** | dsh（`pnpm dsh web`）内嵌 hive-fed-gateway 插件 | 局域网内一台常开机器 |
| **PC（Host）** | `hive-fed-host.mjs` 独立运行器（或装载 dsh 插件） | 每台要入网的电脑 |
| **操作员（你）** | `hive-fedctl.mjs` CLI（第二步起：Web UI） | 任意一台 |

## 一次性准备（已完成，留档）

- 便携工具链：`build\.tools\node-v22.23.2-win-x64`（无需管理员）
- dsh 源码 + 构建：`build\sandbox\deepseek-harness-master\`
- 三个插件包：`build\dsh-plugin\{fed-protocol, fed-gateway, fed-host}`
- gateway/host 插件已装入 dsh 的 **web profile**（`~\.dsh\profiles\web\`）

## 日常启动

### 服务器机器（每次开机）
```powershell
$env:Path = "C:\Users\Administrator.DESKTOP-2O6QH5P\Desktop\build\.tools\node-v22.23.2-win-x64;$env:Path"
cd C:\Users\Administrator.DESKTOP-2O6QH5P\Desktop\build\sandbox\dsh-standard
node node_modules\@deepseek-ai\dsh\lib\bin.js web --no-open
```
启动成功的标志（控制台）：
```
[hive-fed-gateway] listening on ws://127.0.0.1:3081/fed
[hive-fed-gateway] user token file: ~\.hive\gateway-user-token
[hive-fed-gateway] settings source attached: {"port":3081,"bindHost":"127.0.0.1"}
dsh web: http://127.0.0.1:3080/?token=...
```
> Web UI 浏览器访问：`http://127.0.0.1:3080/?token=<上面的token>`
> token 每次启动都会变；同一浏览器会话内刷新页面即可（cookie 仍有效）。
> 局域网其他机器要访问，把监听地址改成 `0.0.0.0`——**现在可以直接在界面里改**，见下面「改配置」

### 每台 PC 机器（接入 = 拷包 → 起进程 → 配对 → 网络）

**第 1 步：把包弄过去**（当前只能拷目录；一键分发是第二步 Center Website 的事）
- 便携 Node：整个 `build\.tools\node-v22.23.2-win-x64` 拷过去即可（或机器上已有 Node ≥ 22）
- 插件包：`build\dsh-plugin\fed-host` 整个目录（`lib/` + `bin/` + `cordis.patch.yml`）
- 依赖：在该目录里跑一次 `npm install`（只装 `ws`；`registry.npmjs.org` 可达）
- **不需要** `fed-protocol`：协议已内联进 `lib/`

**第 2 步：起进程**——两种方式，**同一台机器上二者是同一个设备身份**（token 都在 `~\.hive`）

*A. 装了 dsh（推荐：有界面卡片）*
```powershell
# 在 ~\.dsh\profiles\web\package.json 里登记：
#   dsh.profile.bundles += "hive-fed-host"
#   dependencies       += "hive-fed-host": "file:<fed-host 目录绝对路径>"
cd ~\.dsh\profiles\web ; corepack pnpm install
# 重启那台机器的 dsh web
```
之后在界面里配置：**插件 → 已安装 → 查看 `hive-fed-host` → 组件 `hive-fed-host/host`**
（网关地址 / 设备名称 / fs.read 白名单，改完点保存即时重连，**不用重启**）

*B. 没装 dsh（轻量：只跑一个 node 进程）*
```powershell
node build\dsh-plugin\fed-host\bin\hive-fed-host.mjs `
  --name "PC-3" `
  --gateway "ws://<服务器IP>:3081/fed" `
  --allow-dir "C:\Users\你\Desktop"
```
- `--name`：这台电脑在联邦里的显示名
- `--allow-dir`：**fs.read 白名单**（Agent 只能读这些目录下的文件；CLI 当前支持 1 个，
  界面方式支持逗号分隔的多个）
- 参数只能启动时给，要改就改完重起；要免重启就用 A

**第 3 步：配对**（每台 PC 一次）
- 首次启动会打印 `[hive-fed-host] pairing required: present code XXXXXX`
- 在服务器上批准：`node hive-fedctl.mjs approve XXXXXX`
- PC 端把设备 Token 存到 `~\.hive\device-token.json`，之后自动重连、无需再配对
- 已配对过的机器（`~\.hive` 里有 token）**换用另一种起法也不用重新配对**——实测直接
  `authenticated as host-001`

**第 4 步：网络**
- 同一局域网：先把服务器的**监听地址改成 `0.0.0.0`**（界面改，保存即生效），
  然后 PC 填 `ws://<服务器IP>:3081/fed`；记得放通 3081 端口
- 跨网（不在同一局域网）：见「跨网组网 OpenP2P」，PC 填 `ws://127.0.0.1:<转发端口>/fed`

## 改配置（Web UI，dsh 0.1.6-alpha.2）
所有参数都在界面里改，改完点「保存」即时生效，**不需要重启 dsh**：

**插件 → 已安装 → 查看 `hive-fed-gateway` → 点组件 `hive-fed-gateway/host` → 表单**

| 字段 | 作用 | 说明 |
|---|---|---|
| 联邦端口 | WS 监听端口（默认 3081） | 保存后立即重启监听，已连接的主机会自动重连 |
| 监听地址 | 绑定地址 | 本机测试 `127.0.0.1`；**要让局域网/组网的其他机器连进来，改成 `0.0.0.0`** |

- 表单是**暂存草稿 + 保存**：改完字段只在本地暂存（显示「有未保存的改动」），点「保存」才写入
- 「已覆盖」徽标 = 该字段在用户层有覆盖；点「恢复默认」清除覆盖，回落到组装层默认值
- 写入落在 `~\.dsh\settings.yaml` 的 `hive-gateway:` 段（`hive-host` 同理），重启后自动生效
- 等价的手工方式：直接编辑该 yaml 的对应段（改完 dsh 会自动重载）
- PC 机器装了 `hive-fed-host` 这个 bundle 后，同样的路径（插件 → 查看 `hive-fed-host` →
  组件 `hive-fed-host/host`）可以改网关地址 / 设备名 / fs.read 白名单

> ⚠️ 不要再往 profile 的 `cordis.patch.yml` 里手工加 insert 行：那是组装层，而 bundle
> 已经登记在 profile 的 `dsh.profile.bundles` 里，两边同 id 会让 dsh 启动直接失败
> （`duplicate loader entry id`）

## 配对（每台 PC 只需一次）

操作员在服务器（或任何装了 fedctl 的机器）上：
```powershell
node build\dsh-plugin\fed-gateway\bin\hive-fedctl.mjs approve XXXXXX
```
成功输出 `approved: host-00X (PC-3) caps=[...]`。
PC 端自动保存设备 Token 到 `~\.hive\device-token.json`，之后重启自动重连，无需再配对。

## 派发任务

任务 = 一段 JSON 指令，经 stdin 传给 fedctl（推荐，避免 PowerShell 引号问题）：
```powershell
# 1. 看看谁在线
node build\dsh-plugin\fed-gateway\bin\hive-fedctl.mjs list

# 2. 读取某台电脑上的文件（信息差消除的核心能力）
'{"op":"fs.read","path":"C:/Users/你/Desktop/报表.xlsx.txt"}' |
  node build\dsh-plugin\fed-gateway\bin\hive-fedctl.mjs task PC-3

# 3. 测试连通
'{"op":"echo","message":"在吗"}' | node ...hive-fedctl.mjs task PC-3

# 4. 查询某台电脑的系统状态
'{"op":"sysinfo"}' | node ...hive-fedctl.mjs task PC-3
```
结果以 JSON 回显。`"ok": false` + `"denied": "..."` = 被 host 的权限门拒绝（同时写审计）。

## 安全语义（当前版本）

- **设备 Token**：配对审批后签发，只存哈希；网关重启后 PC 会自动丢弃旧 Token
  （`.stale` 留痕）并重新走配对——这是安全设计，不是故障
- **白名单**：`fs.read` 只能读 `--allow-dir` 下的文件；白名单外一律拒绝 + 双侧审计
- **审计**：`~\.hive\audit.log`（gateway 侧）与 `~\.hive\host-audit.log`（host 侧），
  每条含 traceId，跨机全链路可追
- **用户面认证**：fedctl 用 `~\.hive\gateway-user-token` 认证；loopback 不作为鉴权依据

## 现在还不能做什么（诚实清单 → 对应后续步骤）

| 不能 | 什么时候有 |
|---|---|
| 在 Web UI 里看主机/审批配对/派任务（现在用 fedctl） | 第二步：fed-webui |
| 用自然语言派任务（「帮我看下 PC-3 桌面上的报表」） | 第二步：Main Agent 调度工具 + 你手动配置 LLM 端点（llama.cpp/LM Studio/Ollama 均可） |
| 兼容层回归样本、dsh 插件包安装器 | 第二步：compat Tier 1 |
| 跨网组网（不在同一局域网） | Post-MVP：OpenP2P 编排 |
| 远程插件下发（签名+确认+回滚） | Post-MVP 最后做 |
| 文件同步、Center Website | Post-MVP |

## 常见问题

| 现象 | 原因与处理 |
|---|---|
| host 一直 ECONNREFUSED | 服务器没启动 / 3081 端口不通；先启动服务器 |
| host 提示 `unknown or revoked device token` 后自动重新要配对码 | 正常：网关重启会清 token 库，host 自愈重配对，审批新码即可 |
| fedctl 报 `user token file missing` | 服务器还没启动过（token 文件随网关首次启动生成） |
| 任务返回 `payload_invalid: prompt must be JSON` | prompt 不是合法 JSON；用单引号包裹整串、内层用双引号，或走 stdin |
| 任务返回 `denied: path outside whitelist` | 该路径不在 `--allow-dir` 内；改白名单或换路径 |
