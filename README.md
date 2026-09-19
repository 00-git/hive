# hive — 第一步：装进 dsh

**hive** 是一个跨机器的 AI Agent 联邦。它**没有中心服务器**：每台机器都是一个对等节点，
身份由本机密钥自证，信任由你在两台机器上肉眼比对 6 位数字后建立。

每台机器装完之后：既能被同伴连上，也能连同伴；谁都能向已配对的机器派任务。

---

## 怎么用

1. 在**每台**要加入联邦的机器上，打开 dsh 的聊天输入框
2. 把下面 [📋 安装提示词](#-安装提示词) 整段复制粘贴进去，回车
3. 跟着 agent 的提示走完配置 —— 只有两处需要你亲手做：
   - **输入 OpenP2P 的账号密码**（agent 不该代你输）
   - **核对 6 位数字**（这是安全机制本身，必须人来做）

> 装完一台后，其余机器重复同样的两步。

---

## 📋 安装提示词

> **复制下面整段**（从「你是 hive 安装助手」到结尾），粘贴到 dsh 的输入框里。

```text
你是 hive 联邦的安装助手。请在这台已装好 dsh 的机器上，把 hive 从零装好，并带我完成所有配置。

工作方式要求：
- 每一步都先验证再往下走；任何一步失败就停下来，把原始报错贴给我，不要猜、不要跳过。
- 不要替我输入任何密码或 token；不要把密码写进任何文件、命令或你的回复里。
- 不要静默修改系统设置，不要尝试提权。每步都告诉我：你执行了什么、看到了什么。

背景（省得你摸索）：
- hive 是 dsh 插件，仓库 https://github.com/00-git/hive
- 三个包：dsh-plugin/fed-protocol（协议、身份、信任表）、dsh-plugin/fed-gateway（接收侧）、
  dsh-plugin/fed-host（拨号侧）
- dsh-plugin/fed-peer 是两侧共用的库，不是插件，不需要单独装
- 仓库里已提交构建产物 lib/，正常情况下【不需要构建】
- 一台机器要装 fed-gateway 和 fed-host 两个，才是完整的对等节点
- Node 需要 ≥ 22；Windows 上请用 PowerShell，且【一条命令一行】执行

────────────────────────────────────────
阶段 0 · 环境侦察（只读，先不要改任何东西）
────────────────────────────────────────
1. `node -v`，确认 ≥ 22
2. `corepack pnpm -v`，不可用则 `corepack enable pnpm`
3. 列出 `~/.dsh/profiles/` 下的 profile。`dsh web` 用的是名为 web 的 profile。
4. 读该 profile 的 package.json，报告现在 `dsh.profile.bundles` 里有什么。

把 1~4 的结果汇总给我，然后【停下来等我确认】再继续。

────────────────────────────────────────
阶段 1 · 取源
────────────────────────────────────────
优先 `git clone https://github.com/00-git/hive.git`。
如果 github.com:443 不通，改为下载 https://codeload.github.com/00-git/hive/zip/refs/heads/main
并解压（codeload 通常可直连，不需要代理）。

告诉我 hive 仓库最终的绝对路径。

────────────────────────────────────────
阶段 2 · 装进 profile（把 <REPO> 换成上一步的路径）
────────────────────────────────────────
在该 profile 目录里执行：
corepack pnpm add file:<REPO>/dsh-plugin/fed-protocol file:<REPO>/dsh-plugin/fed-gateway file:<REPO>/dsh-plugin/fed-host

然后编辑该 profile 的 package.json，把这三个名字加进 `dsh.profile.bundles` 数组：
  hive-fed-protocol、hive-fed-gateway、hive-fed-host

⚠️ 改 package.json 必须用 node 读写（例如 node 脚本 JSON.parse/stringify）。
   不要用 PowerShell 的 `Set-Content -Encoding utf8` —— 它会写入 BOM，把 package.json 弄坏，
   之后 dsh 起不来。

────────────────────────────────────────
阶段 3 · 验证装载
────────────────────────────────────────
1. 重启 dsh（或让它重新加载该 profile）
2. 在启动日志里找 hive 的输出行
3. 到 dsh「设置 → 插件」里确认能看到 hive-fed-gateway 与 hive-fed-host
4. 若出现 `duplicate loader entry id`：说明 cordis.patch.yml 里手工加的行和 bundle 自带的行撞了。
   处理：删掉手工加的那行 —— 包已经在 `dsh.profile.bundles` 里，就不需要再手工 insert。

到这里先停下，把结果告诉我。

────────────────────────────────────────
阶段 4 · 配置（逐项问我，改完一项确认生效再问下一项）
────────────────────────────────────────
1. 【本机昵称】这台机器在别人的列表里显示成什么？纯展示，随时可改。
2. 【监听地址】保持**留空**。留空 = 自动探测 VPN 网卡；探测不到就不开监听（这是故意的，
   宁可不通也不意外暴露）。除非我明确说要暴露到别的网卡，否则不要填。
3. 【fs.read 白名单】允许被远程读取的目录有哪些？只填最小必要的，不要图省事填整个盘。
4. 【对端地址】要连哪些机器 —— 先问我用不用 OpenP2P 组网：
   若用：
     a. `node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs fetch`
        （自动下载 openp2p 二进制，不需要我手动放文件）
     b. `node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs join --node <昵称>`
        —— 过程中会问 OpenP2P 账号密码。【请让我自己在终端里输入】，你不要代填。
        输入完，请把回显出来的账号和节点名念给我，提醒我记下来
        （换机器要用同一个账号才能进同一张私有网）
     c. 明确提醒我：openp2p 需要管理员权限，必须由我**自己开一个提权终端**跑一次
        `node <REPO>/dsh-plugin/fed-gateway/bin/hive-p2p.mjs run`
        你不要尝试提权。
     d. 对端地址填 OpenP2P 转发后的本地地址：`ws://127.0.0.1:<src>/fed`

────────────────────────────────────────
阶段 5 · 配对（这一步最容易做错，请严格照做）
────────────────────────────────────────
两台机器互相发现后，双方各自会看到一个【6 位数字】(SAS)。这个数字是防中间人的全部机制。

- 【必须由人来比对】：请明确告诉我「这台机器上显示的 SAS 是 XXXXXX，
  请核对另一台机器屏幕上是不是同一个数」。
- 我说「一样」，你才执行：
  `node <REPO>/dsh-plugin/fed-gateway/bin/hive-fedctl.mjs trust approve <设备ID> <SAS>`
- 我如果说「不一样」，【立刻停止】，不要重试、不要换个数字再试，也不要安慰我说可能是巧合
  —— 数字不一致正是中间人的特征，必须停下来告诉我。

另外：请**不要**建议我把自己屏幕上显示的数字直接输进去。必须是另一边屏幕上的数字。
两个数字一样时它们本来就相同；不一样时，输自己的那个等于确认攻击者。

────────────────────────────────────────
阶段 6 · 验收
────────────────────────────────────────
1. `hive-fedctl peers` 应列出已配对的对端和它们的昵称
2. 派一个小任务试一下，例如：
   `node <REPO>/dsh-plugin/fed-gateway/bin/hive-fedctl.mjs task <昵称> '{"op":"sysinfo"}'`
3. 把结果贴给我
```

---

## 需要你亲手做的只有两件事

| 事项 | 为什么不能代劳 |
|---|---|
| 输入 OpenP2P 账号密码 | 凭据不应经过 AI 的上下文 |
| 核对 6 位数字 (SAS) | **这个比对本身就是安全机制**。中间人转发真公钥会验签失败，用自己的公钥则两边数字不同 —— 只有人能发现后者 |

`openp2p.exe` 声明了 `requireAdministrator`（它要装隧道网卡），所以启动它必须由你在提权终端里做一次。
**获取二进制是全自动的**，只有启动这一步需要提权。

---

## 排障备忘（给 agent 看）

- **构建顺序**（仅当需要从源码重建时）：`fed-protocol` → `fed-peer` → `fed-gateway` / `fed-host`。
  后者用相对路径 import 前者的 `lib/`，靠 tsdown 内联。
- **必须单独跑类型检查**：tsdown 不做类型检查。用 `corepack pnpm exec tsc --noEmit`。
- **`corepack pnpm run build` 即使成功也返回 exit 1**：tsdown 往 stderr 写日志，PowerShell 会当成错误。
  看输出里有没有 `Build complete`，不要看退出码。
- **`pnpm add file:` 是硬链接副本**：改了源码要重新 `pnpm add`，否则跑的还是旧代码。
- **`src/client/index.tsx` 的 tsc 报错是正常的**：浏览器半侧由 esbuild 打包，react 是外部件，
  tsc 找不到它 —— 这是既有噪音，不是你的改动引起的。
- **单机自测**：可以用两个不同的 `--state-dir`、不同端口跑两个节点，走完整配对流程，
  不需要第二台机器就能验证。
