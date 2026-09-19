/**
 * Host settings section (Host half) — 网关地址/设备名/白名单 编辑后即时重连。
 */
import z from './vendor/schemastery.mjs'

export const HOST_SETTINGS_NS = 'hive-host'

export interface HostSettings {
  /** 逗号分隔的对端地址列表（ws://…）。无中心：这里可以填多台机器。 */
  peerUrls: string
  /** 本机昵称，其他机器的主机列表上显示它。纯展示，不参与身份认定。 */
  nickname: string
  /** 逗号分隔的目录列表（fs.read 白名单）。 */
  whitelistDirs: string
  stateIntervalMs: number
}

export const HostSettingsSchema = z.object({
  peerUrls: z.string().default(''),
  nickname: z.string().default(''),
  whitelistDirs: z.string().default(''),
  stateIntervalMs: z.number().default(15_000),
}) as never as z<HostSettings>
