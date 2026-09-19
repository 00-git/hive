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
  // The card carries a comma-separated string; the client wants a list. Keeping
  // the split here means neither side has to know the other's shape.
  const peerRaw = value.peerUrls
  const peerUrls = typeof peerRaw === 'string'
    ? peerRaw.split(',').map((entry) => entry.trim()).filter((entry) => entry.length > 0)
    : Array.isArray(value.peerUrls)
      ? [...value.peerUrls]
      : []
  return {
    peerUrls,
    nickname: typeof value.nickname === 'string' && value.nickname.length > 0 ? value.nickname : undefined,
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
      if (settings === undefined) {
        console.log('[hive-fed-host] settings service unavailable; running without a settings surface')
        return
      }
      const base: HostSettings = {
        peerUrls: Array.isArray(currentConfig.peerUrls) ? currentConfig.peerUrls.join(',') : '',
        nickname: currentConfig.nickname ?? '',
        whitelistDirs: Array.isArray(currentConfig.whitelistDirs)
          ? currentConfig.whitelistDirs.join(',')
          : typeof currentConfig.whitelistDirs === 'string'
            ? currentConfig.whitelistDirs
            : '',
        stateIntervalMs: currentConfig.stateIntervalMs ?? 15_000,
      }
      let source: () => Partial<HostSettings> = () => base
      // alpha.2 exposes the canonical helper as a method on the settings
      // service; dsh 0.1.1 shipped it as a package export (`installSettingsSection`)
      // and never put it on the service, so calling the method there fails with
      // "installSection is not a function" and the deployment silently loses its
      // settings surface. Both versions build the helper on the same low-level
      // `register(ns, schema, { base })` + `scope.watch` pair, which is what the
      // fallback uses.
      const installSection = (
        service: Record<string, unknown>,
        ns: string,
        schema: unknown,
        entry: unknown,
        hooks: { setSource: (current: () => HostSettings) => void; onChange: () => void },
      ): boolean => {
        if (typeof service.installSection === 'function') {
          ;(service.installSection as (c: unknown, n: string, s: unknown, e: unknown, h: unknown) => void)(ctx, ns, schema, entry, hooks)
          return true
        }
        if (typeof service.register !== 'function') return false
        const scope = (service.register as (n: string, s: unknown, o: unknown) => { get?: () => HostSettings; watch?: (cb: () => void) => void })(ns, schema, { base: entry })
        if (scope === undefined || typeof scope.get !== 'function') return false
        hooks.setSource(() => scope.get!())
        hooks.onChange()
        scope.watch?.(() => hooks.onChange())
        return true
      }

      const installed = installSection(settings as unknown as Record<string, unknown>, HOST_SETTINGS_NS, HostSettingsSchema, base, {
        setSource: (current) => {
          // Handed a STABLE thunk answering the currently authoritative value;
          // holding the thunk (not a snapshot) is what lets a committed edit
          // reach the reconnection.
          source = current
        },
        onChange: () => {
          const next = normalize({ ...config, ...base, ...(source() ?? {}) })
          console.log(`[hive-fed-host] settings changed: peerUrls=${(next.peerUrls ?? []).join(',')} nickname=${next.nickname ?? ''}; redialing`)
          currentConfig = next
          restart()
        },
      })
      console.log(`[hive-fed-host] settings section installed: ${installed}`)
    })
  }
}

export { HostClient } from './client.js'
export type { HostConfig } from './client.js'
