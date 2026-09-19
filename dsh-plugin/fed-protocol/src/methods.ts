/**
 * Federation method and event catalogs.
 *
 * Naming is A-class benchmarked against dsh ctx.* service method conventions:
 * domain-prefixed, verb-last where a noun reads better, closed sets.
 * Side-effecting methods REQUIRE an idempotencyKey on the request frame.
 */
import type { DeviceId, PublicKeyB64 } from './identity.js'

export const FedMethod = {
  /** any peer → acceptor: first frame on a connection (role + protocol range + public key). */
  CONNECT: 'connect',
  /** dialing peer → acceptor: sign the acceptor's nonce — step 2 of every handshake. */
  AUTHENTICATE: 'authenticate',
  /** local user surface → acceptor: peers whose signature verified but whose SAS is unconfirmed. */
  TRUST_PENDING_LIST: 'trust.pending.list',
  /** local user surface → acceptor: an operator compared the SAS; pin this peer. */
  TRUST_APPROVE: 'trust.approve',
  /** local user surface → acceptor: drop a peer from the trust table (local, instant, no sync). */
  TRUST_REVOKE: 'trust.revoke',
  /** local user surface → acceptor: read the trust table. */
  TRUST_LIST: 'trust.list',
  /** peer → acceptor: advertise caps and current state summary (post-connect). */
  HOST_REGISTER: 'host.register',
  /** peer → acceptor: periodic state digest push (also available as an event). */
  HOST_STATE_REPORT: 'host.state.report',
  /** acceptor → peer: dispatch one directed task. Side-effecting. */
  AGENT_TASK: 'agent.task',
  /** either direction: cancel an in-flight task. Side-effecting. */
  AGENT_TASK_CANCEL: 'agent.task.cancel',
  /** acceptor → peer: ask a bounded introspection question (no side effects). */
  AGENT_ASK: 'agent.ask',
  /** local user surface → acceptor: send a chat turn. Side-effecting. */
  CHAT_SEND: 'chat.send',
  /** local user surface → acceptor: read synchronized session history (dsh session log mirror). */
  CHAT_HISTORY: 'chat.history',
  /** local user surface → acceptor: list trusted peers with their last state digests. */
  HOST_LIST: 'host.list',
  /** any peer → any peer: exchange known peers so the mesh heals without a directory. */
  PEER_EXCHANGE: 'peer.exchange',
} as const

export type FedMethod = (typeof FedMethod)[keyof typeof FedMethod]

export const FedEvent = {
  /** acceptor → local user surfaces: a peer's signature verified but its SAS is unconfirmed. */
  TRUST_PENDING: 'trust/pending',
  /** acceptor → a pending peer: an operator compared the SAS and pinned this peer. */
  TRUST_GRANTED: 'trust/granted',
  /** acceptor → a pending peer: the operator rejected it, or the window expired. */
  TRUST_DENIED: 'trust/denied',
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
  /** peer table delta so the mesh heals without any directory. */
  PEER_UPDATED: 'peer/updated',
} as const

export type FedEvent = (typeof FedEvent)[keyof typeof FedEvent]

/**
 * Methods whose req frames MUST carry idempotencyKey (security/consistency invariant).
 *
 * trust.approve is deliberately NOT here: it is keyed by deviceId and its
 * effect is set-like (approving twice is one row), so a replay is a no-op by
 * construction rather than something the key machinery has to rescue.
 */
export const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set([
  FedMethod.AGENT_TASK,
  FedMethod.AGENT_TASK_CANCEL,
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

/**
 * Host state digest — the anti-信息差 payload injected into the main agent's context.
 *
 * Written by the peer about ITSELF (single writer per row), so no conflict
 * resolution is needed: a stale copy is simply overwritten by the next report.
 * `nickname` is the owning peer's own label and carries no authority — every
 * receiver keys off deviceId, so a peer cannot promote itself by renaming.
 */
export interface HostStateDigest {
  deviceId: DeviceId
  /** Operator-facing label, freely editable by the owning peer. Never an identity source. */
  nickname: string
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

/**
 * trust.approve params — the operator's out-of-band confirmation, mirrored on the wire.
 *
 * The operator must type the digits displayed on the OTHER machine, not the ones
 * shown locally. That is the whole anti-MITM mechanism: with an attacker in the
 * middle the two screens show different digits, so the typed value fails the
 * local comparison and the peer is refused. Pasting the local value would
 * confirm the attacker instead.
 */
export interface TrustApproveParams {
  deviceId: DeviceId
  /** Must equal the SAS computed locally from both public keys. */
  sas: string
  /** Optional label the operator assigns locally; ignored when absent. */
  nickname?: string
}

/**
 * One peer as advertised by another peer (peer.exchange).
 *
 * A HINT, never an authorization. Receiving a row here must NOT create trust:
 * the receiver dials the address and runs the full handshake + SAS comparison
 * exactly as if a human had typed it. That is what keeps a malicious peer from
 * populating the mesh with identities it vouches for.
 */
export interface PeerAnnouncement {
  deviceId: DeviceId
  publicKey: PublicKeyB64
  nickname: string
  /** Where the ANNOUNCER reaches this peer (an already-local forward address when tunneled). */
  address: string
  /** Whether the ANNOUNCER trusts it — informational only; the receiver decides for itself. */
  trusted: boolean
  lastSeenMs: number
}
