/**
 * Federation method and event catalogs.
 *
 * Naming is A-class benchmarked against dsh ctx.* service method conventions:
 * domain-prefixed, verb-last where a noun reads better, closed sets.
 * Side-effecting methods REQUIRE an idempotencyKey on the request frame.
 */

export const FedMethod = {
  /** any peer → gateway: first frame on a connection (role + protocol range + token). */
  CONNECT: 'connect',
  /** host → gateway: present a pairing code, request a device token. */
  PAIR_REQUEST: 'pair.request',
  /** user surface → gateway: approve a pending pairing code. */
  PAIR_APPROVE: 'pair.approve',
  /** gateway → user surfaces: a pairing code awaits approval. */
  PAIR_PENDING_EVENT: 'pair.pending',
  /** host → gateway: advertise caps and current state summary (post-connect). */
  HOST_REGISTER: 'host.register',
  /** host → gateway: periodic state digest push (also available as an event). */
  HOST_STATE_REPORT: 'host.state.report',
  /** gateway → host: dispatch one directed task. Side-effecting. */
  AGENT_TASK: 'agent.task',
  /** gateway → host / host → gateway: cancel an in-flight task. Side-effecting. */
  AGENT_TASK_CANCEL: 'agent.task.cancel',
  /** gateway → host: ask a bounded introspection question (no side effects). */
  AGENT_ASK: 'agent.ask',
  /** user surface → gateway: send a chat turn. Side-effecting. */
  CHAT_SEND: 'chat.send',
  /** user surface → gateway: read synchronized session history (dsh session log mirror). */
  CHAT_HISTORY: 'chat.history',
  /** user surface → gateway: list paired hosts with their last state digests. */
  HOST_LIST: 'host.list',
} as const

export type FedMethod = (typeof FedMethod)[keyof typeof FedMethod]

export const FedEvent = {
  /** pairing outcome for the requesting host (approved token / denied reason). */
  PAIR_RESULT: 'pair/result',
  /** pairing code awaiting operator approval (gateway → user surfaces). */
  PAIR_PENDING: 'pair/pending',
  /** agent.stream — streamed agent output for a task/chat turn. */
  AGENT_STREAM: 'agent.stream',
  /** tool lifecycle mirrors (dsh tool/call, tool/result shape). */
  TOOL_CALL: 'tool/call',
  TOOL_RESULT: 'tool/result',
  /** host presence transitions (online/offline/busy). */
  PRESENCE: 'presence',
  /** task lifecycle updates (pending/running/done/failed/cancelled). */
  TASK_UPDATED: 'task/updated',
  /** host state digest broadcast. */
  HOST_STATE: 'host/state',
} as const

export type FedEvent = (typeof FedEvent)[keyof typeof FedEvent]

/** Methods whose req frames MUST carry idempotencyKey (security/consistency invariant). */
export const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set([
  FedMethod.AGENT_TASK,
  FedMethod.AGENT_TASK_CANCEL,
  FedMethod.PAIR_REQUEST,
  FedMethod.CHAT_SEND,
])

/** Task lifecycle states mirrored from dsh turn/step semantics. */
export type TaskState = 'pending' | 'running' | 'done' | 'failed' | 'cancelled'

/** One directed task dispatch (gateway → host). */
export interface AgentTaskParams {
  taskId: string
  /** Instruction for the host agent. The host runs it under local approval. */
  prompt: string
  /** Minimum caps the host must have been granted at pairing for this task. */
  requiredCaps: readonly string[]
  deadlineMs: number
  traceId: string
}

/** Bounded introspection question (gateway → host). */
export interface AgentAskParams {
  questionId: string
  prompt: string
  deadlineMs: number
  traceId: string
}

/** Host state digest — the anti-信息差 payload injected into the main agent's context. */
export interface HostStateDigest {
  deviceId: string
  displayName: string
  os: string
  lanAddress: string
  cpuLoadPct?: number
  memTotalMb?: number
  memFreeMb?: number
  diskSummaries?: readonly { readonly mount: string; readonly freeMb: number }[]
  reportedAtMs: number
}

/** Side-effect methods must be dispatched with these delivery fields present. */
export function requiresIdempotencyKey(method: string): boolean {
  return IDEMPOTENT_METHODS.has(method)
}
