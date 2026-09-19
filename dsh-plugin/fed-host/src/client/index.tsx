/**
 * Browser half: hive-fed-host's configuration seat on the Plugins page.
 *
 * Each bundle owns its own card, so an executor machine configures itself here
 * rather than from the gateway's card (the two halves run on different machines).
 * The seat is the row this bundle's cordis.patch.yml declares:
 *
 *   插件 → 已安装 → 查看 hive-fed-host → hive-fed-host/host → 表单
 *
 * Writes are staged (a draft becomes a document change once, on 保存) and the
 * card mounts only while the Host serves the `hive-host` namespace — a machine
 * running the standalone runner instead of the dsh plugin shows nothing.
 *
 * Bundle purity: `react` is the sole runtime import; the settings scope and the
 * slot registry arrive as cordis services (the client bundle purity gate forbids
 * cross-plugin value imports).
 *
 * NOTE: the staged-form machinery below is deliberately mirrored in
 * hive-fed-gateway's browser half. The two packages ship independently and the
 * purity gate keeps them from importing each other, so the shared shape is
 * duplicated on purpose; extract it into a shared package if a third card lands.
 */
import { useEffect, useState } from 'react'

/** Settings namespace this half installs (see settings-host.ts). */
const NS = 'hive-host'
/**
 * alpha.2's seat: one row's configuration on the Plugins page, keyed
 * `<package>#<rowId>` as this bundle's cordis.patch.yml declares the row. The
 * page asks for `summary` (the one-liner) and `page` (the form).
 */
const SLOT_ROW = 'plugins.row.config'
const KEY_ROW = 'hive-fed-host#hive-fed-host/host'
/**
 * Pre-alpha.2 seat: the Plugins settings section's card list, keyed by the
 * settings namespace the card edits, with no view to answer — the card owns its
 * own chrome. dsh 0.1.1-rc.2 and 0.1.6-alpha.1 declare this one.
 *
 * Both are registered: a seat no deployment declares never dispatches, so one
 * bundle serves every dsh version in the fleet instead of pinning a version.
 */
const SLOT_CARD = 'settings.plugin.item'

/** Client-side state of one settings namespace. */
interface ScopeSnapshot {
  status: 'loading' | 'ready' | 'unavailable'
  value: Record<string, unknown> | undefined
  /** Raw user layer; a field's PRESENCE here is what marks it overridden. */
  user: unknown
  writable: boolean
}

/** The bound namespace scope this card reads and writes through. */
interface ScopeLike {
  getSnapshot(): ScopeSnapshot
  subscribe(listener: () => void): () => void
  set(field: string, value: unknown): Promise<void>
  unset(field: string): Promise<void>
}

/** The served-namespace directory every settings surface derives from. */
interface DescribeFaceLike {
  getSnapshot(): { view?: { namespaces: readonly { ns: string }[] } }
  subscribe(listener: () => void): () => void
  ensure(): Promise<void>
}

/** The write one field's staged text performs when the card is saved. */
type FieldWrite = { kind: 'set'; value: unknown } | { kind: 'clear' }

/** One staged draft: what the user typed, or a clear back to the composition layer. */
type Draft = { kind: 'set'; text: string } | { kind: 'clear' }

/** How one field converts between its stored value and its draft text. */
interface FieldSpec {
  field: string
  label: string
  hint: string
  placeholder: string
  /** Text shown while neither a draft nor a stored value stands. */
  fallback: string
  /**
   * The write this text stages, or undefined when the text is not a value this
   * field accepts — which blocks the save rather than discarding the draft.
   */
  parse(text: string): FieldWrite | undefined
}

/** A free-text field; an empty draft clears it back to the composition layer. */
function textField(text: string): FieldWrite | undefined {
  const trimmed = text.trim()
  return trimmed === '' ? { kind: 'clear' } : { kind: 'set', value: trimmed }
}

const FIELDS: readonly FieldSpec[] = [
  {
    field: 'gatewayUrl',
    label: '网关地址',
    hint: 'ws://<网关IP>:3081/fed；经 OpenP2P 组网时填本地转发端口。保存后立即重连。',
    placeholder: 'ws://127.0.0.1:3081/fed',
    fallback: 'ws://127.0.0.1:3081/fed',
    parse: (text) => {
      const write = textField(text)
      // A typo here would otherwise be silently replaced by the default at the
      // host half, so refuse anything that is not a websocket URL.
      if (write?.kind === 'set' && !/^wss?:\/\/\S+$/i.test(String(write.value))) return undefined
      return write
    },
  },
  {
    field: 'deviceName',
    label: '设备名称',
    hint: '网关主机列表上的显示名；留空则回落到主机名。',
    placeholder: 'PC-2',
    fallback: '',
    parse: textField,
  },
  {
    field: 'whitelistDirs',
    label: 'fs.read 白名单',
    hint: '逗号分隔的目录；只有这些目录下的文件会被 agent 读取，留空表示仅允许进程工作目录。',
    placeholder: 'C:\\Users\\你\\Desktop',
    fallback: '',
    parse: textField,
  },
]

/** The staged form one card renders and commits. */
interface CardForm {
  text(field: string): string
  overridden(field: string): boolean
  invalid(field: string): boolean
  readonly dirty: boolean
  readonly invalidAny: boolean
  readonly saving: boolean
  readonly failed: boolean
  edit(field: string, text: string): void
  reset(field: string): void
  save(): void
  discard(): void
}

/**
 * Read one namespace scope without polling: the scope replaces its snapshot and
 * notifies, so a render is always a projection of the latest accepted section.
 * @param scope - the bound namespace scope.
 * @returns the current snapshot.
 */
function useScope(scope: ScopeLike): ScopeSnapshot {
  const [snapshot, setSnapshot] = useState<ScopeSnapshot>(() => scope.getSnapshot())
  useEffect(() => {
    setSnapshot(scope.getSnapshot())
    return scope.subscribe(() => setSnapshot(scope.getSnapshot()))
  }, [scope])
  return snapshot
}

/**
 * Whether the user layer carries a field.
 * @param user - the raw user layer, as the Host stored it.
 * @param field - field name inside the namespace section.
 * @returns true when the user layer owns an entry for this field.
 */
function userCarries(user: unknown, field: string): boolean {
  return typeof user === 'object' && user !== null && Object.prototype.hasOwnProperty.call(user, field)
}

/**
 * Stage what the user types and write it only on save.
 * @param scope - the bound namespace scope drafts are written to.
 * @param snapshot - the latest scope snapshot drafts are seeded from.
 * @returns the form state and its actions.
 */
function useCardForm(scope: ScopeLike, snapshot: ScopeSnapshot): CardForm {
  const [drafts, setDrafts] = useState<Record<string, Draft>>({})
  const [saving, setSaving] = useState(false)
  const [failed, setFailed] = useState(false)

  const specOf = (field: string): FieldSpec | undefined => FIELDS.find((spec) => spec.field === field)
  const draftOf = (field: string): Draft | undefined => drafts[field]

  /** The plan a staged draft computes to; undefined blocks the save. */
  const planOf = (field: string, draft: Draft): FieldWrite | undefined => {
    if (draft.kind === 'clear') return { kind: 'clear' }
    return specOf(field)?.parse(draft.text)
  }

  const plans = Object.entries(drafts).map(([field, draft]) => planOf(field, draft))

  const discard = (): void => {
    setDrafts({})
    setFailed(false)
  }

  const save = (): void => {
    if (saving) return
    if (plans.some((plan) => plan === undefined)) return
    const writes = Object.entries(drafts).map(([field, draft]) => {
      const plan = planOf(field, draft)
      return () => (plan?.kind === 'set' ? scope.set(field, plan.value) : scope.unset(field))
    })
    setSaving(true)
    setFailed(false)
    void (async () => {
      try {
        for (const write of writes) await write()
        // Re-seed from what the Host accepted rather than predicting the outcome.
        setDrafts({})
      } catch {
        // A save that did not land keeps its drafts so they can be corrected.
        setFailed(true)
      } finally {
        setSaving(false)
      }
    })()
  }

  return {
    text: (field) => {
      const draft = draftOf(field)
      if (draft !== undefined) return draft.kind === 'clear' ? '' : draft.text
      const stored = snapshot.value?.[field]
      if (stored === undefined || stored === null) return specOf(field)?.fallback ?? ''
      return String(stored)
    },
    overridden: (field) => {
      const draft = draftOf(field)
      // A staged edit answers for itself: the badge previews the save.
      if (draft !== undefined) return draft.kind === 'set'
      return userCarries(snapshot.user, field)
    },
    invalid: (field) => {
      const draft = draftOf(field)
      if (draft === undefined) return false
      return planOf(field, draft) === undefined
    },
    dirty: Object.keys(drafts).length > 0,
    invalidAny: plans.some((plan) => plan === undefined),
    saving,
    failed,
    edit: (field, text) => setDrafts((current) => ({ ...current, [field]: { kind: 'set', text } })),
    reset: (field) => setDrafts((current) => ({ ...current, [field]: { kind: 'clear' } })),
    save,
    discard,
  }
}

const LABEL: React.CSSProperties = { fontSize: 13, fontWeight: 600, color: 'var(--dsw-alias-label-primary, inherit)' }
const HINT: React.CSSProperties = { fontSize: 12, lineHeight: '18px', color: 'var(--dsw-alias-label-secondary, rgba(128,128,128,.9))' }
const ERROR: React.CSSProperties = { ...HINT, color: 'var(--dsw-alias-state-error-primary, inherit)' }
const INPUT: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  padding: '5px 8px',
  border: '0.5px solid var(--dsw-alias-border-l3, rgba(128,128,128,.45))',
  borderRadius: 6,
  background: 'transparent',
  color: 'inherit',
  font: 'inherit',
}

/**
 * One field: its label, hint, the draft it renders, and — when one stands — the
 * overridden badge with the reset that stages a clear.
 * @param props - the field spec, the form, and the read-only flag.
 * @returns the labelled control.
 */
function Field(props: { spec: FieldSpec; form: CardForm; readOnly: boolean }): React.ReactElement {
  const { spec, form, readOnly } = props
  const bad = form.invalid(spec.field)
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 168px) minmax(0, 1fr)', gap: '12px', alignItems: 'start' }}>
      <div>
        <div style={LABEL}>{spec.label}</div>
        <div style={HINT}>{spec.hint}</div>
      </div>
      <div>
        <input
          style={bad ? { ...INPUT, borderColor: 'var(--dsw-alias-state-error-primary, rgba(200,60,60,.8))' } : INPUT}
          value={form.text(spec.field)}
          placeholder={spec.placeholder}
          disabled={readOnly}
          aria-invalid={bad || undefined}
          onChange={(event) => form.edit(spec.field, event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') form.save()
          }}
        />
        {bad ? <div style={ERROR}>这个取值不被接受，保存已阻止</div> : null}
        {form.overridden(spec.field) ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
            <span style={{ ...HINT, border: '0.5px solid var(--dsw-alias-border-l4, rgba(128,128,128,.45))', borderRadius: 4, padding: '0 4px' }}>已覆盖</span>
            <button
              type="button"
              onClick={() => form.reset(spec.field)}
              disabled={readOnly}
              style={{ ...HINT, background: 'none', border: 0, padding: 0, cursor: readOnly ? 'default' : 'pointer', textDecoration: 'underline' }}
            >
              恢复默认
            </button>
          </div>
        ) : null}
      </div>
    </div>
  )
}

/**
 * Render the executor's configuration page: its controls and the save that
 * writes every staged edit.
 * @param props - the form and the namespace state it renders against.
 * @returns the form.
 */
function Card(props: { form: CardForm; snapshot: ScopeSnapshot }): React.ReactElement {
  const { form, snapshot } = props
  const readOnly = !snapshot.writable
  const saveStyle: React.CSSProperties = {
    padding: '4px 12px',
    borderRadius: 6,
    border: '0.5px solid var(--dsw-alias-border-l3, rgba(128,128,128,.45))',
    background: 'var(--dsw-alias-bg-layer-3, rgba(128,128,128,.12))',
    color: 'inherit',
    font: 'inherit',
    cursor: 'pointer',
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: '4px 0' }}>
      {readOnly ? (
        <p style={HINT}>这条连接把偏好保存在本进程内，改动无法写入 Host 的设置文档。</p>
      ) : null}
      {FIELDS.map((spec) => (
        <Field key={spec.field} spec={spec} form={form} readOnly={readOnly} />
      ))}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        {form.failed ? (
          <span style={ERROR}>保存未生效，草稿已保留：请检查取值或重试。</span>
        ) : (
          <span style={HINT}>{form.dirty ? '有未保存的改动' : '已与 Host 同步'}</span>
        )}
        <span style={{ display: 'flex', gap: 8 }}>
          <button type="button" onClick={form.discard} disabled={!form.dirty || form.saving} style={saveStyle}>
            放弃
          </button>
          <button
            type="button"
            onClick={form.save}
            disabled={readOnly || !form.dirty || form.invalidAny || form.saving}
            style={{ ...saveStyle, opacity: readOnly || !form.dirty || form.invalidAny ? 0.5 : 1 }}
          >
            {form.saving ? '保存中…' : '保存'}
          </button>
        </span>
      </div>
    </div>
  )
}

/**
 * Render the row's one-liner.
 * @param props - the namespace snapshot the line is projected from.
 * @returns the summary text.
 */
function Summary(props: { snapshot: ScopeSnapshot }): React.ReactElement {
  const value = props.snapshot.value ?? {}
  const gatewayUrl = String(value.gatewayUrl ?? 'ws://127.0.0.1:3081/fed')
  const deviceName = typeof value.deviceName === 'string' && value.deviceName.length > 0 ? value.deviceName : '未命名'
  const overridden = FIELDS.some((spec) => userCarries(props.snapshot.user, spec.field))
  return <>{`→ ${gatewayUrl} · ${deviceName}${overridden ? ' · 已覆盖' : ''}`}</>
}

/**
 * The row's configuration entry. Two deployments ask two different questions:
 * alpha.2's Plugins page asks for a one-liner (`summary`) or its own page's body
 * (`page`, where the page draws the title), while the older card list asks for
 * nothing and expects a self-contained card.
 * @param props - the view the page asks for (absent on the older seat) and the
 * scope its registration injects.
 * @returns the one-liner, the form, or null while the namespace is not served.
 */
export function HiveHostRow(props: { view?: 'summary' | 'page'; scope: ScopeLike }): React.ReactElement | null {
  const { scope, view } = props
  const snapshot = useScope(scope)
  const form = useCardForm(scope, snapshot)
  if (snapshot.status === 'unavailable') return null
  if (view === 'summary') return <Summary snapshot={snapshot} />
  const card = <Card form={form} snapshot={snapshot} />
  if (view === 'page') return card
  return (
    <div style={{ padding: '4px 0' }}>
      <div style={LABEL}>hive 主机接入</div>
      <div style={HINT}>这台电脑连向联邦网关的参数；必须自备 fs.read 白名单目录。</div>
      {card}
    </div>
  )
}

export const inject = ['slots', 'locale', 'remote', 'settingsScope']

/**
 * Mount the card into every seat this deployment declares, while the Host
 * serves the namespace, and retire them when either goes away.
 * @param ctx - the browser plugin context.
 */
export function apply(ctx: unknown): void {
  const c = ctx as {
    settingsScope?: {
      bind(spec: { namespace: string }): ScopeLike
      describe(): DescribeFaceLike
    }
    slots?: {
      inject(slot: string, register: () => unknown): unknown
      register(options: Record<string, unknown>, component: unknown): () => void
    }
    effect?(run: () => () => void, label: string): unknown
  }
  if (c.slots === undefined || c.settingsScope === undefined) return
  const slots = c.slots
  const scope = c.settingsScope.bind({ namespace: NS })
  const face = c.settingsScope.describe()

  /** Register one seat, tolerating a seat this dsh does not declare at all. */
  const mount = (slot: string, key: string): (() => void) | undefined => {
    try {
      return slots.inject(slot, () => slots.register({
        name: slot,
        key,
        inject: () => ({ scope }),
      }, HiveHostRow)) as () => void
    } catch {
      // An unknown slot name only means this deployment never had that seat.
      return undefined
    }
  }

  let mounted: Array<() => void> = []
  const sync = (): void => {
    const served = new Set(face.getSnapshot().view?.namespaces.map((view) => view.ns) ?? [])
    if (served.has(NS) && mounted.length === 0) {
      mounted = [mount(SLOT_ROW, KEY_ROW), mount(SLOT_CARD, NS)].filter((off): off is () => void => typeof off === 'function')
    } else if (!served.has(NS) && mounted.length > 0) {
      for (const off of mounted) off()
      mounted = []
    }
  }

  const unsubscribe = face.subscribe(sync)
  const teardown = (): void => {
    unsubscribe()
    for (const off of mounted) off()
    mounted = []
  }
  void face.ensure()
  sync()
  c.effect?.(() => teardown, 'hive-fed-host: configuration seats')
}
