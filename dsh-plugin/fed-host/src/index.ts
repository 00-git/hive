/**
 * hive-fed-host — host-half dsh plugin.
 *
 * 可关闭: unmounting the plugin stops the client via the plugin lifecycle.
 * The same client also runs standalone (`hive-fed-host` bin) for machines
 * where the operator prefers not to boot dsh (可替换 principle).
 * Settings card (hive-host): gatewayUrl/deviceName/whitelistDirs 编辑后即时重连。
 */
import { HostClient, type HostConfig } from './client.js'
import { HOST_SETTINGS_NS, HostSettingsSchema, type HostSettings } from './settings-host.js'

export const name = 'hive-fed-host'

export interface Config extends HostConfig {}

function normalize(value: Partial<HostSettings> & HostConfig): HostConfig {
  const whitelistRaw = value.whitelistDirs
  const whitelistDirs = typeof whitelistRaw === 'string' && whitelistRaw.trim().length > 0
    ? whitelistRaw.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0)
    : Array.isArray(value.whitelistDirs)
      ? value.whitelistDirs
      : undefined
  return {
    gatewayUrl: typeof value.gatewayUrl === 'string' && value.gatewayUrl.length > 0 ? value.gatewayUrl : 'ws://127.0.0.1:3081/fed',
    deviceName: typeof value.deviceName === 'string' && value.deviceName.length > 0 ? value.deviceName : undefined,
    stateDir: typeof value.stateDir === 'string' ? value.stateDir : undefined,
    whitelistDirs,
    stateIntervalMs: typeof value.stateIntervalMs === 'number' && value.stateIntervalMs > 0 ? value.stateIntervalMs : 15_000,
  }
}

export function apply(ctx: unknown, config: Config = {}): void {
  const c = ctx as {
    provide?: (key: string, value: unknown) => void
    inject?: (deps: readonly string[], cb: (scoped: unknown) => void) => void
  }
  if (typeof c.provide !== 'function') {
    throw new Error('hive-fed-host: host context does not expose provide(); not a cordis context')
  }

  let currentConfig = normalize(config)
  let listener: { stop(): void } | undefined

  const start = (): void => {
    const client = new HostClient(currentConfig)
    client.start()
    listener = client
  }

  /**
   * One stable service for the plugin's whole lifetime: a cordis fiber refuses a
   * second `provide()` of the same name, so re-publishing a fresh handle on every
   * reconnection threw inside the settings attach and took the settings
   * registration down with it. Reconnecting swaps the client behind the handle.
   */
  const handle = {
    stop: (): void => {
      listener?.stop()
      listener = undefined
    },
  }
  const restart = (): void => {
    handle.stop()
    start()
  }

  start()
  c.provide('fedHost', handle)

  if (typeof c.inject === 'function') {
    c.inject(['settings'], (scoped: unknown) => {
      const settings = (scoped as { settings?: {
        installSection: (
          ctx: unknown,
          ns: string,
          schema: unknown,
          initial: unknown,
          handlers: {
            /** alpha.2 hands the active value as a thunk, not as a value. */
            setSource: (current: () => HostSettings) => void
            onChange: () => void
          },
        ) => void
      } }).settings
      if (settings === undefined) return
      const base: HostSettings = {
        gatewayUrl: currentConfig.gatewayUrl ?? 'ws://127.0.0.1:3081/fed',
        deviceName: currentConfig.deviceName ?? '',
        whitelistDirs: Array.isArray(currentConfig.whitelistDirs)
          ? currentConfig.whitelistDirs.join(',')
          : typeof currentConfig.whitelistDirs === 'string'
            ? currentConfig.whitelistDirs
            : '',
        stateIntervalMs: currentConfig.stateIntervalMs ?? 15_000,
      }
      let source: () => Partial<HostSettings> = () => base
      settings.installSection(ctx, HOST_SETTINGS_NS, HostSettingsSchema, base, {
        setSource: (current) => {
          // alpha.2 hands a STABLE thunk answering the currently authoritative
          // value. Holding the thunk — not a snapshot of its first answer — is
          // what lets a committed edit reach the reconnection, because
          // `scope.watch` fires `onChange` without re-running `setSource`.
          source = current
        },
        onChange: () => {
          const next = normalize({ ...config, ...base, ...(source() ?? {}) })
          console.log(`[hive-fed-host] settings changed: gatewayUrl=${next.gatewayUrl} deviceName=${next.deviceName}; reconnecting`)
          currentConfig = next
          restart()
        },
      })
    })
  }
}

export { HostClient } from './client.js'
export type { HostConfig } from './client.js'
