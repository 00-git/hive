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
  nickname: string
}

export const GatewaySettingsSchema = z.object({
  /** Federation WS 端口（改动即时重启监听）。 */
  port: z.number().default(3081),
  /**
   * 监听地址。**留空 = 自动探测 VPN 网卡**；探测不到就不开监听（fail-closed）。
   * 只有你要故意暴露到其他网卡时，才手填地址（如 0.0.0.0）。
   */
  bindHost: z.string().default(''),
  /** 本机昵称，其他机器的主机列表上显示它。纯展示，不参与身份认定。 */
  nickname: z.string().default(''),
}) as never as z<GatewaySettings>
