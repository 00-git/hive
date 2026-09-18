/**
 * Host settings section (Host half) — 网关地址/设备名/白名单 编辑后即时重连。
 */
import z from './vendor/schemastery.mjs'

export const HOST_SETTINGS_NS = 'hive-host'

export interface HostSettings {
  gatewayUrl: string
  deviceName: string
  /** 逗号分隔的目录列表（fs.read 白名单）。 */
  whitelistDirs: string
  stateIntervalMs: number
}

export const HostSettingsSchema = z.object({
  gatewayUrl: z.string().default('ws://127.0.0.1:3081/fed'),
  deviceName: z.string().default(''),
  whitelistDirs: z.string().default(''),
  stateIntervalMs: z.number().default(15_000),
}) as never as z<HostSettings>
