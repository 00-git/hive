# hive-fed-protocol

hive 联邦线协议（openclaw 式三帧 req/res/event）+ 设备 Token 鉴权硬约束 + 与 dsh `ctx.*`
会话数据同步所需的共享词表。纯逻辑、零运行时依赖、可替换（传输在 gateway/host 包中）。

English | 中文（本文件）

## Summary

hive 的第一个 dsh 插件包。提供 `fedProtocol` 服务：

- **三帧协议**：`req` / `res` / `event`（+ `event.ack` 背压），全帧入站校验（wire 边界）
- **鉴权硬约束**：身份只能由「配对时签发的设备 Token」解析（恒定时间比较、只存哈希）；
  loopback / 已配对传输 / 任意包头都**不得**作为唯一鉴权依据（禁止清单）
- **协议基础项**：版本协商、deadline、幂等键（副作用方法强制）、traceId、seq/ack 背压
- **dsh 数据同步词表**：工具调用/结果镜像、会话历史同步、主机状态摘要（信息差消除载荷）

## Model Experience

- What the model sees: nothing. 本包不进入任何模型请求；仅搬运字节并校验边界。
- KV Cache effect: none.

## Known Limitations and Deferred Work

- 无 cordis 类型合并（本包不依赖 cordis，保持可独立发布）——gateway/host 用
  `inject: ['fedProtocol']` + 本包类型访问服务
- 未签名插件下发载荷在协议层拒绝（安全模型 1），签名体系本体在第二步交付
