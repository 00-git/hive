# hive

跨机器 AI Agent 联邦，以 dsh 插件形态交付。

无中心服务器。每台机器是一个对等节点：身份由本机密钥对自证，信任由两名操作员比对 6 位数字后建立。
每台机器同时具备接收侧（`fed-gateway`）与拨号侧（`fed-host`）。

- 仓库：https://github.com/00-git/hive
- 包：`fed-protocol`（协议、身份、信任表）、`fed-peer`（共享库，非插件）、`fed-gateway`、`fed-host`
- 已提交构建产物 `lib/`，常规安装**无需构建**

---

## 快速开始

在 dsh 输入框粘贴：

```
阅读仓库根目录 README.md，按「安装」执行；逐项询问我「配置」中的内容；按「配对」完成互信；最后按「验收」自查。
```

---

## 安装

假设仓库路径为 `<REPO>`，profile 为 `~/.dsh/profiles/<name>`（`dsh web` 使用 `web`）。

1. 校验环境
   - `node -v` ≥ 22
   - `corepack pnpm -v`；不可用则 `corepack enable pnpm`
2. 读取 profile 的 `package.json`，记录现有 `dsh.profile.bundles`
3. 取源
   - 首选 `git clone https://github.com/00-git/hive.git`
   - 若 `github.com:443` 不通：下载
     `https://codeload.github.com/00-git/hive/zip/refs/heads/main` 并解压（codeload 通常可直连）
4. 装入 profile
   ```
   corepack pnpm add file:<REPO>/dsh-plugin/fed-protocol file:<REPO>/dsh-plugin/fed-gateway file:<REPO>/dsh-plugin/fed-host
   ```
5. 向该 profile 的 `dsh.profile.bundles` 追加三个名字：
   `hive-fed-protocol`、`hive-fed-gateway`、`hive-fed-host`
   - 用 node 读写 JSON。**不要用 PowerShell `Set-Content -Encoding utf8`**：会写入 BOM 并损坏 `package.json`
6. 重启 dsh，在「设置 → 插件」确认两个插件已加载
   - 若报 `duplicate loader entry id`：删除 profile `cordis.patch.yml` 中手工新增的对应条目
     （包已在 `dsh.profile.bundles` 中声明时，无需手工 insert）

每台需要加入联邦的机器重复以上步骤。

---

## 配置

进入「设置 → 插件」，逐项询问并配置：

| 项 | 取值 | 说明 |
|---|---|---|
| 本机昵称 | 任意 | 其他机器列表上显示的名称。纯展示，不参与身份认定 |
| 监听地址 | **留空** | 留空 = 自动探测 VPN 网卡；探测不到则**不开监听**（fail-closed）。不要填 `0.0.0.0` |
| fs.read 白名单 | 目录列表 | 允许被远程读取的目录。只填必要项 |
| 对端地址 | `ws://127.0.0.1:<src>/fed` | 每台对端一条。经 OpenP2P 时填本地转发端口 |

### 组网（OpenP2P）

```
node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs fetch
node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs join --node <本机昵称>
```

- `fetch` 自动获取二进制，无需人工放置
- `join` 过程会询问 OpenP2P 账号密码：**由用户本人在终端输入**
- 同账号即同私有网。账号密码需用户自行留存，换机时复用
- 启动需管理员权限（`openp2p.exe` 声明 `requireAdministrator`）：由用户自行提权执行
  ```
  node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs run
  ```

---

## 配对

握手完成后，双方各自显示一个 6 位数字（SAS），由两台机器**各自的公钥**推导得出。

1. 在一台机器上执行 `hive-fedctl trust pending`，读取「本机 SAS」与设备 ID
2. 请操作员比对两台机器**屏幕上**的两个数字
3. 一致 → 执行
   ```
   hive-fedctl trust approve <设备ID> <另一端屏幕上显示的数字>
   ```
4. **不一致 → 立即停止。** 不得重试、不得改用其他数字、不得视为偶发问题

两台机器各需确认一次。确认由本地信任表持久化，且不依赖 dsh 运行状态。

> 中间人转发真实公钥时无法通过签名校验（无对应私钥）；改用自身公钥时两端 SAS 不同。
> 因此 SAS 比对是仅存的检测手段，且只能由人完成。
> 若输入**本机屏幕**上的数字，等于确认攻击者。

---

## 验收

```
node <REPO>/dsh-plugin/fed-gateway/bin/hive-fedctl.mjs trust list
node <REPO>/dsh-plugin/fed-gateway/bin/hive-fedctl.mjs peers
node <REPO>/dsh-plugin/fed-gateway/bin/hive-fedctl.mjs task <昵称> '{"op":"sysinfo"}'
```

预期：`trust list` 列出已确认对端；`peers` 中以 `●` 标记在线对端；`task` 返回结果。

---

## 约束

- 不代用户输入密码或 token；不将凭据写入任何文件、命令或回复
- 不尝试提权
- SAS 不一致时立即停止并交由用户判断
- 不静默修改系统设置；每步说明执行内容与观察结果
- Windows 上每条命令单独一行执行

---

## 排障

| 现象 | 原因与处理 |
|---|---|
| `duplicate loader entry id` | profile `cordis.patch.yml` 的手工条目与 bundle 声明冲突：删除手工条目 |
| `package.json` 损坏 / dsh 无法启动 | 用 PowerShell `Set-Content -Encoding utf8` 写入过 BOM：以 UTF-8 无 BOM 重写 |
| 监听未启动 | 未探测到 VPN 网卡。启动 OpenP2P，或显式填写监听地址 |
| 对端 `pending` 后无进展 | 另一台机器尚未确认。互信需**两侧各自**确认 |
| 修改源码后行为未变 | `pnpm add file:` 为硬链接副本：重新执行步骤 4 |
| 需要从源码重建 | 顺序固定：`fed-protocol` → `fed-peer` → `fed-gateway`/`fed-host` |
| 类型检查 | tsdown 不做类型检查，须单独执行 `corepack pnpm exec tsc --noEmit` |
| `tsc` 报 `client/index.tsx` 错误 | 浏览器半侧由 esbuild 打包，react 为外部件。属既有情况 |

单机验证（无需第二台机器）：以不同 `--state-dir` 与端口运行两个节点，走完整配对流程。
