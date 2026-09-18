/**
 * hive-fed-gateway — host-half dsh plugin.
 *
 * 可替换/可关闭: the WS server lives behind the provided `fedGateway` service
 * (ctx.provide, mount-lifetime) and restarts live when the user edits the
 * settings card (设置 → 插件配置 → hive 联邦网关). Unmounting the plugin
 * stops the listener; the host dsh runs fine without it.
 */
import { GatewayServer, type GatewayConfig } from './server.js'
import { GATEWAY_SETTINGS_NS, GatewaySettingsSchema, type GatewaySettings } from './settings-gateway.js'

export const name = 'hive-fed-gateway'

/** Loader-layer config (cordis.patch.yml). The settings card layers on top. */
export interface Config extends GatewayConfig {}

interface GatewayHandle {
  stop(): void
  readonly port: number
}

function normalizeConfig(value: Partial<GatewaySettings> & GatewayConfig): GatewayConfig {
  const port = typeof value.port === 'number' && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65_535
    ? value.port
    : 3081
  const bindHost = typeof value.bindHost === 'string' && value.bindHost.length > 0 ? value.bindHost : '127.0.0.1'
  return {
    port,
    bindHost,
    auditPath: typeof value.auditPath === 'string' ? value.auditPath : undefined,
    stateDir: typeof value.stateDir === 'string' ? value.stateDir : undefined,
  }
}

export function apply(ctx: unknown, config: Config = {}): void {
  const c = ctx as {
    provide?: (key: string, value: unknown) => void
    inject?: (deps: readonly string[], cb: (scoped: unknown) => void) => void
  }
  if (typeof c.provide !== 'function') {
    throw new Error('hive-fed-gateway: host context does not expose provide(); not a cordis context')
  }

  let currentConfig = normalizeConfig(config)
  let listener: GatewayServer | undefined
  let boundPort = currentConfig.port ?? 3081

  const start = (): void => {
    const server = new GatewayServer(currentConfig)
    server.start()
    listener = server
    boundPort = currentConfig.port ?? 3081
  }

  /**
   * One stable service for the plugin's whole lifetime.
   *
   * A cordis fiber refuses a second `provide()` of the same name, so publishing a
   * fresh handle on every listener restart threw inside the settings attach — and
   * the escaping exception tore down the whole settings registration with it (the
   * namespace stopped being served, so the Plugins page lost the row's card).
   * Restarting swaps the server behind the handle instead of re-providing.
   */
  const handle: GatewayHandle = {
    stop: () => {
      listener?.stop()
      listener = undefined
    },
    get port(): number {
      return boundPort
    },
  }
  const restart = (): void => {
    handle.stop()
    start()
  }

  start()
  c.provide('fedGateway', handle)

  // Settings card (设置 → 插件配置): edits land in the settings document and
  // onChange restarts the listener live — no dsh restart (model-proxy pattern).
  if (typeof c.inject === 'function') {
    c.inject(['settings'], (scoped: unknown) => {
      const settings = (scoped as { settings?: {
        installSection: (
          ctx: unknown,
          ns: string,
          schema: unknown,
          initial: unknown,
          handlers: {
            validate?: (value: unknown) => void
            /**
             * alpha.2 hands the active value as a STABLE thunk answering the
             * currently authoritative value — the resolved settings section while
             * one is attached, the composition entry otherwise. Hold the thunk;
             * a snapshot of its first answer goes stale, because `scope.watch`
             * fires `onChange` without re-running `setSource`.
             */
            setSource: (current: () => GatewaySettings) => void
            onChange: () => void
          },
        ) => void
      } }).settings
      if (settings === undefined) return
      /** Schema defaults, layered under the composition entry the loader resolved. */
      const defaults: GatewaySettings = { port: 3081, bindHost: '127.0.0.1' }
      /** The composition entry: the patch row's config, and the install fallback. */
      const entry: GatewaySettings = {
        port: typeof config.port === 'number' ? config.port : defaults.port,
        bindHost: typeof config.bindHost === 'string' ? config.bindHost : defaults.bindHost,
      }
      /**
       * The active configuration source. alpha.2 hands a STABLE thunk that always
       * answers the currently authoritative value — the resolved settings section
       * while one is attached, the composition entry otherwise. Holding the thunk
       * (rather than a snapshot of its first answer) is what lets a committed edit
       * reach the listener, because `scope.watch` fires `onChange` without
       * re-running `setSource`.
       */
      let source: () => Partial<GatewaySettings> = () => entry
      try {
        settings.installSection(ctx, GATEWAY_SETTINGS_NS, GatewaySettingsSchema, entry, {
          validate: (value) => {
            const port = (value as GatewaySettings).port
            if (!Number.isInteger(port) || port < 1 || port > 65_535) {
              throw new Error('端口必须是 1-65535 的整数')
            }
          },
          setSource: (current) => {
            source = current
            // Attach answers with the resolved document; detach answers with the
            // composition entry (the settings scope is no longer in effect).
            console.log(`[hive-fed-gateway] settings source attached: ${JSON.stringify(source() ?? {})}`)
          },
          onChange: () => {
            // The settings document may carry sparse sections — merge over schema
            // defaults and the composition entry so filtered fields never regress
            // and no loader-level key is dropped.
            const next = normalizeConfig({ ...config, ...defaults, ...(source() ?? {}) })
            if (next.port === currentConfig.port && next.bindHost === currentConfig.bindHost) return
            console.log(`[hive-fed-gateway] settings changed: port=${next.port} bindHost=${next.bindHost}; restarting listener`)
            currentConfig = next
            restart()
          },
        })
      } catch (error) {
        // A failed install leaves the plugin running without its settings
        // surface. Say so loudly: an escaping error here also takes the
        // namespace registration down, so the Plugins page loses the card too.
        console.error(`[hive-fed-gateway] settings section could not be installed: ${String((error as Error)?.message ?? error)}`)
      }
    })
  }
}

export { GatewayServer } from './server.js'
export type { GatewayConfig } from './server.js'
