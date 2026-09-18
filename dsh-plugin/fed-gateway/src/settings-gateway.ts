/**
 * Gateway settings section (Host half) — the 端口/绑定地址 users edit from
 * 设置 → 插件配置. Schema is the dsh-vendored schemastery so validation and
 * the settings document agree byte-for-byte (A 类对标: model-proxy).
 */
import z from './vendor/schemastery.mjs'

export const GATEWAY_SETTINGS_NS = 'hive-gateway'

export interface GatewaySettings {
  port: number
  bindHost: string
}

export const GatewaySettingsSchema = z.object({
  /** Federation WS 端口（改动即时重启监听）。 */
  port: z.number().default(3081),
  /** 监听地址；P2P/局域网部署改 0.0.0.0。 */
  bindHost: z.string().default('127.0.0.1'),
}) as never as z<GatewaySettings>
