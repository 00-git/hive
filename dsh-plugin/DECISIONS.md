# hive 决策记录 — 阶段 0/1.0 基线（2026-09-17）

> D-005 起为**第一步实现期决策**，依据「新设计必须向 user 提问/审核」规则，
> 由 user 指令「一次搞完，不要让我重复」授权批量决定，全部标注于下，供事后追认。

## D-001 基座路线：vendor + patch（非提取内核）
- dsh 从源码完整跑通：pnpm install (1m44s) → pnpm run build（240 client 产物）→ `pnpm dsh web` 启动成功
- Web UI 基线验证：http://127.0.0.1:3080 中文界面正常（工作区/会话/设置/标准模式）
- 真实生态插件安装成功：`dsh plugin add dsh-plugin-model-proxy --profile default`（npm 生态活跃，
  社区市场 8000+ 插件）
- **结论**：黑盒路线走通，按计划降级为 vendor + patch，不提取内核

## D-002 快照锚定
- 来源：codeload zip（git 与 objects.githubusercontent.com 在本机不可达；api.github.com / codeload 可用）
- 快照：deepseek-harness master @ commit `0d1f50007f9bca3f52b06e1c3074fa14d5fb0720`
- 版本：**0.1.6-alpha.1** ≥ 0.1.2-alpha.1（CVE-2026-82533 修复版本锚定满足）
- zip 无 .git：构建元数据经 `DSH_CLIENT_COMMIT_HASH=0d1f5000…` 注入真实提交哈希（构建脚本
  `scripts/client-build-environment.ts` 支持该覆盖变量，`repositoryGitDirty` 无 git 元数据时优雅返回 undefined）
- CVE-2026-82533 / #587 / #1220：快照内无 CVE 明文记录（社区讨论区为准，user 提供）；
  vendor 路线使用上游已发布快照；第二步以「CVE 复现用例」作为回归验证

## D-003 沙箱环境（全部便携，无管理员依赖）
```
build/
├── .tools/                  # 便携工具链
│   ├── node-v22.23.2-win-x64/   # Node ≥ 22.19 ✅（engines: ^22.19.0 || >=24）
│   ├── node.zip / dsh-master.zip
│   └── （MinGit 下载失败——objects.githubusercontent.com 不可达，改用 zip 快照）
├── dsh-plugin/              # 第一步：fed-protocol / fed-gateway / fed-host 开发区
└── sandbox/deepseek-harness-master/   # dsh 源码（vendor+patch 基座）
```
- pnpm：corepack 启用，仓库 packageManager 锁定 pnpm@11.7.0（自动切换）
- dsh profile：`~\.dsh\profiles\default`（真实插件已装入）
- 终端环境恢复命令（新终端必执行）：
  `$env:Path = "…\build\.tools\node-v22.23.2-win-x64;$env:Path"; $env:COREPACK_ENABLE_DOWNLOAD_PROMPT="0"; $env:DSH_CLIENT_COMMIT_HASH="0d1f5000…"; cd …\sandbox\deepseek-harness-master`

## D-004 已知注意项（来自 AGENTS.md，开发 fed-* 时必须遵守）
- 函数插件导出 name/inject/Config/apply，**无默认导出**；服务类才默认导出
- 可选服务用 `ctx.get(name)`；`ctx.<name>` 属性访问必须先声明 inject
- 无硬编码可调参数：部署差异走可校验的 Config（cordis.yml）
- 跨边界 id 用品牌化类型（dsh-brand），模型可见 ⟺ 可从 session log 重建
- 非 trivial 变更必须附 Agent Note；客户端文案走 i18n 字典（verify-client-ui-i18n 门禁）
- 安全不变量保持固定（不属于可配置项）——与我们的「禁止清单」吻合

## D-005 ��������������ڣ�ctx.provide() ���� ctx.effect()
- ʵ�⣺ctx.effect(fn) �󶨵��� apply �Ķ��� fiber��apply ���ؼ����� dispose����
  gateway �� WS �������������������رգ�netstat 3081 �޼�����
- �޸������� ctx.provide('fedGateway', ��) ���У��������� = ��������ڣ����� model-proxy��
- ��ѵ����ֿ���䣻host ͬ��

## D-006 pnpm file: �����ǰ�װʱ����
- profile �� pnpm add file:<���ذ�> �Ḵ�ƹ��������Դ���ؽ������ remove+add ˢ�¸���
- �˿ӵ����޸��汾����δ��Ч������ѭ���̶�Ϊ��build �� re-add �� restart��

## D-007 host ˫��̬����
- dsh-plugin ��ڣ���ʽ��̬���ڶ������ã�+ bin/hive-fed-host.mjs ����������
- MVP �����ö���������ģ��ڶ�̨����������ڶ��� dsh profile �Ķ˿�/���Ӷȣ�
- ���滻ԭ���ʵ����ͬһ�ͻ��˴������ dsh �ڻ������������

## D-008 ҵ��ܾ����ŷ�����
- ������δ���� = ��������ִ�е�ҵ���� ok:false��res �ŷ� ok:true��
- ��Э��/����ʧ�ܲ��� res ok:false + FedError
- ���� host ��ҵ��ܾ��Ž� ok:false �ŷ� �� gateway decodeFrame ���� �� ���� gateway
  catch �������� bug��frame δ���壩�� **���� dsh ���̱���**�����������޸���
  - host��ҵ��ܾ��� ok:true �ŷ�
  - gateway��catch �ڲ�������������δ֪����� INTERNAL ֡����Ϣѭ���������ף�

## D-009 host Token ����
- ��������/token ����պ�host �־� Token �� UNAUTHENTICATED �ܾ� ��
  �Զ��������� Token������ .stale ���ۣ��� �������������������
- ��������ջ������� = ���ر�� + host ��������ԣ���������룬����Ա�ٴ�������

## D-010 fedctl �û���
- ���� CLI��fed-gateway �� bin��������������ʱд��� user token ��֤����ֹ�嵥��
  loopback ����Ϊ��Ȩ���ݣ�
- ֧�� list / approve / task��prompt ֧�ֲ����� stdin��PS 5.1 ����ת�岻�ɿ���
  stdin Ϊ�Ƽ�·�����������ӡ�� stdout �� exit 1

## ��һ�����ս����2026-09-17��
| ���� | ��� |
|---|---|
| ��ԣ������ 780281 �� ���� �� Token ǩ���� | ? host-001 (PC-2) |
| echo ���� | ? "hello across machines" |
| fs.read �������ڣ�DECISIONS.md 2991B�� | ? ȫ�Ļش� |
| fs.read �������⣨C:/Windows/win.ini�� | ? deny + ��� |
| δ֪�����ɷ���PC-99�� | ? task_not_found |
| ���˫д��gateway audit.log + host host-audit.log�� | ? traceId ��ͨ |

## D-011 ���ÿ���user ��Թ��������û�˿ڡ��Ļ�Ӧ��
- ���������ע�� settings �ڣ�hive-gateway: port/bindHost��hive-host: gatewayUrl/deviceName/
  whitelistDirs/stateIntervalMs����onChange ��ʱ��������/�������� dsh ������
- ������룺fed-gateway �� src/client/index.tsx��esbuild ���� dsh �հ�������ʽ
  ��window.__ModuleLoader__.load({id, factory(require)})����react Ϊ loader ע���ⲿ��
- ʵ�⣺���� �� ������� ������Ⱦ��hive �������ء������ֶ��뵱ǰֵ��ȷ
- ���죺��Ƭ writable=false������ģʽ���飬д��ͨ��δͨ����hive-host ��ͬ������ע��
- schemastery �� dsh vendor ������src/vendor/schemastery.mjs������pnpm file: ָ��
  dsh workspace �ڰ��ᴥ�� workspace ��������D-006 ���壩

## D-012 OpenP2P ��������user ָ����ֱ����p2p����
- bin/hive-p2p.mjs��init������ config.json��˽������ ShareBandwidth=0��PC ������
  ����ת�� 127.0.0.1:3082 �� ���ؽڵ�:3081��+ run�����������ƣ�
- �������Ķ���fed-host �� gatewayUrl ���� ws://127.0.0.1:3082/fed ���� P2P ����
  ������ host ���ÿ���ģ����Ͽ��滻ԭ��
- openp2p �����Ʋ��Զ����أ������������ƣ��������� ~/.hive/openp2p/openp2p.exe �� run
- δ���������޷������������κη���ģ��/�����������˽Ҫ��

## D-013 ���س־û�����Ӧ ERR_CONNECTION_REFUSED -102 ���ϣ�
- ����dsh ����δ���У�3080 �޼����������������������˿��޷��񡹣����������
  ���ش�ǰΪ���ڴ�̬������ = user token �����ɣ�Web UI URL ʧЧ��+ �豸ע�����գ�������ԣ�
- �޸���gateway-user-token ���������ļ����豸ע������� device-registry.json
  ��ֻ�� token HASH + ����/caps��D-004 ���岻�䣩��register/revoke ʱԭ����д
- ʵ�⣺�������� �� PC-2 �ִ洢 Token �Զ����� �� connect.host allow����������ԣ���
  echo ����������Web UI URL �ȶ�
- ��ά���壺�Ժ��ճ�ֻ�������������̣�dsh web + �� PC �� hive-fed-host����
  �����һ���Զ���

## D-014 ��׼�����л���user ָ�������Բ�Ҫ��Դ�빹����
- ����ִ��ƫ�������Ի���ӦΪ�ٷ� npm ��������Դ�빹����Դ�빹�������� dsh �ڲ��Ų飩
- ��׼������build\sandbox\dsh-standard\ �� npm i @deepseek-ai/dsh@alpha��0.1.6-alpha.2��
  �����ͬ����registry ͨ���ɴGitHub release ͨ�����ɴﲻӰ�죩
- ������node_modules\.bin\dsh.cmd web --no-open������·�����ã�npx �ڱ������ɿ���
- ʵ�⣺�ٷ���ֱ�Ӽ��� web profile ��� hive-fed-protocol/gateway����Ķ�����
  ���� 3081 ������PC-2 ƾ D-013 �־û�ע��������������ҳ����� DeepSeek Harness
- �ٷ����������Դ� @deepseek-ai/schemastery ���� ���ÿ� Schema ��Ȼ���ݣ���֤ A ��Ա���ȷ��

## D-015 alpha.2 UI ���죨��Ӧ���������ȥ�ˡ���
- ���ȫ�����ڣ���׼������alpha.2����������������� �� �Ѱ�װ(2)��hive-fed-gateway��
  hive-fed-protocol�������������ÿ��أ���ȫ�ֲ���б����߾��������á������� 3081 �����У�
  PC-2 �����ӡ�֮ǰ 404 �ǲ��� URL ��ʽ������ʵ URL �� loader id �� rev ��ϣ��
- alpha.2 �ع�������ҳ��alpha.1 �ġ�������á���ҳ��settings.plugin.item ����Ⱦ�����ٳ��֣�
  ��Ϊ�����ò�����б� + �����������������壨�ٷ� dsh-plugin-manager��
- ���죨�汾���䣩�����ǵ����ÿ������� alpha.2 ���¹��ص㣨����ɲ�����������ã���
  Ӱ������������ UI�����ǲ�����ܱ���

## D-016 alpha.2 插件配置席位：改挂「插件页 → 组件行」席位
- 现象：alpha.2 下我们原注册进 `settings.plugin.item` 的两张卡片完全不渲染
- 实证：`hive-fed-gateway/client.js` **确实已被加载**（首页下发的 59 个客户端模块含它），
  所以不是没加载，而是槽位名失效：alpha.2 取消了 `settings.plugin.item`，改由
  `dsh-client-ui-plugin-manager` 声明三个席位；官方包内注释明确「第三方 bundle 的配置
  belongs in `plugins.bundle.config` or `plugins.row.config`」
- 三席位：`plugins.item`（官方 host-plane 页面专用，第三方禁用）、
  `plugins.bundle.config`（keyed=包名，渲染在 bundle 页描述与组件列表之间）、
  `plugins.row.config`（keyed=`<包名>#<行id>`）
- **决策（user 拍板）：走 `plugins.row.config`**，key = `hive-fed-gateway#hive-fed-gateway/host`
  —— 席位即组件行本身：key 未注册时该行只是文本，注册后才变成可点入口
  （`has: row => ledger.rows.has(key)`）。备选 bundle 席位少一次点击，未采用
- **交互（user 拍板）：暂存草稿 + 保存/放弃**，对齐 alpha.2「每次设置写入都是带 revision
  栅栏的持久文档变更」的语义；含「已覆盖」徽标与「恢复默认」（= unset 回组装层）；
  弃用原「失焦即写」
- 卡片只在宿主服务该命名空间时注册（订阅 `ctx.settingsScope.describe()`，官方同款 sync 模式），
  未服务则整条不注册，不会留空卡
- 验收（全绿）：插件 → 已安装 → 查看 hive-fed-gateway → 配置 hive-fed-gateway/host →
  改端口保存 → 启动日志出现 `settings changed` + `netstat` 显示新端口 + `~/.dsh/settings.yaml`
  落盘；「恢复默认」撤销后无残留

## D-017 宿主半侧两个缺陷：改端口/改地址不生效的根因
- **(a) 把 thunk 当值**：alpha.2 的 `setSource(current: () => T)` 给的是**活 thunk**
  （装一次、永远回答当前权威值）。旧码 `{...current}` 展开函数得 `{}`，等于每次都读默认值，
  `onChange` 判定「无变化」直接 return —— 监听永不重启
- **(b) 二次 provide**：`restart()` 里每次 `c.provide('fedGateway', handle)`，而 cordis
  **同一 fiber 同名服务只能 provide 一次**，抛 `service "fedGateway" has been registered at
  <hive-fed-gateway>`；该异常从 `installSection` 里逃出，连带掀掉整个设置注册
  （命名空间消失 → 插件页的卡片也消失）。修法：provide 一个**稳定门面**，重启时换内部实例
- 两处均已修（fed-gateway 与 fed-host 同款问题一起修）
- 实证：`settings source attached:{bindHost:"0.0.0.0"}` → `settings changed` → 监听 0.0.0.0:3081；
  改端口 → 0.0.0.0:3085；恢复默认 ×2 → 回 127.0.0.1:3081。四次状态迁移全部正确
- 附带修复：profile 的 `cordis.patch.yml` 手工 insert 与 bundle 自带 row 同 id，导致
  `duplicate loader entry id: hive-fed-protocol/host` 启动即崩 → 清掉手工 insert
  （bundle 已在 `dsh.profile.bundles` 里就够了）
- 环境事实：pnpm `file:` 依赖是**硬链接**副本 —— esbuild 就地覆盖会同步到 profile，
  tsdown「先删后建」不会，所以**重建后要在 profile 目录跑 `corepack pnpm install --offline`**

## D-018 fed-host 增加浏览器半侧（每台 PC 可自行在界面改配置）
- 背景：row 席位是「每个 bundle 拥有自己的卡」，而执行端与网关端分属不同机器，
  fed-host 必须自带浏览器半侧，PC 上的人才能自己改网关地址/设备名/白名单
- 实现：`fed-host/src/client/index.tsx`（席位 `hive-fed-host#hive-fed-host/host`，
  命名空间 `hive-host`）+ `build-client.mjs`（esbuild 闭包工厂，loader id `hive-fed-host`）
  + package.json 增 `./client` 导出、`dsh.client` 配置、devDep esbuild
- 字段：网关地址（**校验必须是 ws/wss URL**，避免打错后被宿主的默认值静默兜底）、
  设备名称、fs.read 白名单；`stateIntervalMs` 故意不暴露（内部节拍，非用户参数）
- 验收（实测）：装进 web profile → 卡片渲染（摘要 `→ ws://127.0.0.1:3081/fed · PC-2`）→
  白名单从空改为 `…\Desktop` 保存 → **同一个 fs.read 请求由 `deny: outside whitelist`
  变为 `allow {bytes:6942}`**，两侧审计同一 traceId
- 接入事实（实测）：设备 token 在 `~\.hive\device-token.json`，**同一台机器上
  「standalone 运行器」与「dsh 插件」共用同一个设备身份**——换起法不需重新配对
- 债：表单机制与 fed-gateway 的浏览器半侧重复（client 包纯度门禁禁止互相 import，
  故有意重复）；等第三张卡出现时抽共享包

## D-019 跨 dsh 版本兼容：双席位注册 + 自适应设置节安装
- 背景：.19 那台机器跑的是 dsh **0.1.1-rc.2**（比本机 alpha.2 早三代），实测"插件功能全通但没有配置卡片"
- 客户端半侧差异（两代席位完全不同，已实测）：
  | 版本 | 席位 | key | 组件 props |
  |---|---|---|---|
  | 0.1.1-rc.2 / 0.1.6-alpha.1 | `settings.plugin.item`（设置→插件→插件配置） | **命名空间** | **无 view**（卡片自带外观） |
  | 0.1.6-alpha.2+ | `plugins.row.config`（插件页→组件行） | `<包名>#<行id>` | `view: 'summary' \| 'page'` |
  - 决策：**两个席位都注册**，未声明的席位永不派发 → 天然自适应，不锁版本（符合"兼容 dsh"目标）
- 宿主半侧差异（更隐蔽，异常被 cordis 吞掉）：
  - alpha.2：`ctx.settings.installSection(owner, ns, schema, entry, hooks)`（服务上的方法）
  - 0.1.1：`installSettingsSection(ctx, ns, schema, entry, hooks)`（**包导出函数**，服务上没有这个方法）
  - 照旧写法在 0.1.1 上抛 `settings.installSection is not a function`，被吞 → 表现"插件能用但没界面"
  - 决策：写**自适应安装器**——优先用服务方法，缺失时回落到两版共有的底层
    `settings.register(ns, schema, { base })` + `scope.get()` / `scope.watch()`；
    **不 import** `dsh-settings`（插件包没有该依赖，运行时会解析失败）
- 两版一致的部分（无需适配）：`setSource(current: () => T)` 活 thunk + `onChange()`；
  客户端 `settingsScope.describe()`；服务名 `settings`；cordis `ctx.inject(deps, cb)`
- 验收（同一份产物，两个版本都对）：
  - .19（0.1.1）：设置→插件→插件配置 出现「hive 主机接入」卡片；改设备名保存 → 宿主日志
    `settings changed` → 重连并以上报名 `PC-19-A` 出现在审计里
  - 本机（alpha.2）：插件页组件行卡片照常（`监听 0.0.0.0:3081 · 已覆盖`），零回归
- 运维事实：SSH 会话启动的进程会随会话断开被杀（须用 WMI `Win32_Process Create` 才能脱离）；
  目标机执行策略禁 `.ps1`（npm/pnpm 走 `.cmd`）；这两条已记入 `dsh-version-compat` 记忆

## D-020 去中心化：自证身份 + SAS 互信（协议 v2，硬切）
- 触发：user 指出「这是去中心化项目，没有 center server 时怎么同步」
- **关键认识**：线协议**本来就是对称的** —— `#handleConnect` 只接受 `role: 'host' | 'user'`，
  **接受方从不声明自己**。所以「谁都能当 gateway」在协议层已成立，gateway 是**角色**不是**服务器**。
  真正的中心化只在三处：① 身份签发 ② 目录（registry） ③ 消息转发
- user 决策（全部取严格档，均经提问确认）：
  | 决策点 | 选定 |
  |---|---|
  | 去中心程度 | 只做拓扑 + 身份，状态暂不进 CRDT（每台机器单写自己，本身无冲突） |
  | 首次见面信任 | **必须 SAS 指纹核对**，不做 TOFU |
  | 旧 token | **硬切废弃**，现有两台机器重新配对 |
  | listener 暴露面 | **只在 VPN 中暴露**；探测不到 VPN 地址就不开监听（fail-closed） |
  | 派发权限 | **仅已配对的电脑**（信任表 = 派发白名单，一表两用） |
  | 跨网 | 一律 OpenP2P；未注册者由程序自动获取二进制并引导注册 |
  | 计划任务 | 手动在提权终端执行（不生成自提权脚本、不静默写系统） |
- 身份模型：`deviceId = base32(sha256(公钥))[:16]`，密钥对自证，**无签发方**。
  换密钥即换身份，因此**没有需要同步的吊销列表**；拒绝一个对端 = 本地删一行
- **互相认证**（原设计的真实缺陷）：初版只有拨号方签名 → **接受方可被冒充**。
  改为双方互相挑战（acceptor 签 dialer 的 clientNonce，搭在 challenge 帧上），往返数不变
- **SAS 为什么有效**（已推演 + 测试覆盖）：中间人转发真公钥 → 无对应私钥 → 签名失败；
  改用自身公钥 → 两端 SAS 不同。两条路都堵死。残余风险是**流程性**的：
  操作员若输入**本机屏幕**上的数字 = 确认攻击者（文档与提示词均写死此警告）
- 信任表是**文件即共享介质**：同一台机器上网关与主机是两个进程，共享 `trusted-peers.json`；
  每次操作前重读，两个进程无需网络即可收敛。CLI 因此是纯文件读写器，dsh 没开也能批准。
  代价：批准来自**另一个进程**，没有回调可挂 → 双方各加 2s 轮询扫描才让决策对**活跃连接**生效
  （撤销尤其不能等重连）
- E2E 抓到的两个真实缺陷（`fed-gateway/verify-two-node.mjs`，单机双节点）：
  1. 拨号方把**自己的昵称**当成对端的 —— `hello.peer` 描述的是拨号方自己，且接受方昵称原本
     根本没在协议里传过。修：`ChallengeOk.acceptorNickname` + `HandshakeDeps.selfNickname`
  2. **撤销后对端仍显示在线** —— 撤销时提前 `#peerConns.delete`，使 close 处理器
     `if (get(id) !== conn) return` 提前返回，`registry.unbind` 永不执行。修：新增 `#dropPeer()`
- **跨包 branded 类型陷阱**（编译期真实故障，值得记）：`fed-peer` 若把 `fed-protocol`
  内联进自己的 `.d.ts`，TS 会看到两份 `DeviceId` 且**互相不可赋值**。修法：
  1. `fed-peer` 的 tsdown 用 `outDir: 'lib'` + `external: [/fed-protocol/]`
     （相对路径 `../../fed-protocol` 从 `lib/` 出发才解析得到）
  2. **gateway/host 只从 `../../fed-peer/lib/index.js` 导入**，绝不直接导 `fed-protocol`
- 验证：三套共 **94 项断言全绿**（身份 43 + 握手 34 + 单机双节点 17），
  覆盖：签名重放/角色互换/密钥掉包/被替换的 SAS/未验证即排队/nonce 作废/撤销切断活跃连接
- 交付形态：`build/README.md` 承载完整安装流程，提示词**自足**（自带仓库地址与取源回退，
  因为 agent 在全新机器上不持有本仓库）；两处必须人工：输入 OpenP2P 账号密码、比对 SAS
- 已知债：`openp2p.exe` 声明 `requireAdministrator`，启动必须人工提权一次（获取二进制已全自动）；
  网关/主机 bundle 各自内联协议副本（branded 类型不受影响，但因导入路径统一故无实际冲突）

