//#region src/auth.d.ts
/** Opaque device token issued at pairing. Branded: never a bare string. */
declare const deviceTokenBrand: unique symbol;
type DeviceToken = string & {
  readonly [deviceTokenBrand]: true;
};
/** Stable device identity minted by the gateway at pairing approval. */
declare const deviceIdBrand: unique symbol;
type DeviceId = string & {
  readonly [deviceIdBrand]: true;
};
/** Capability names a host may grant at pairing. Closed set (security invariant). */
declare const FedCapability: {
  /** host accepts agent.task dispatch and runs it under local approval. */
  readonly TASK_EXEC: "task.exec";
  /** host answers agent.ask introspection questions. */
  readonly TASK_ASK: "task.ask";
  /** host streams state summaries (host.state). */
  readonly STATE_REPORT: "state.report";
  /** host may receive signed plugin install requests (host-side confirm still required). */
  readonly PLUGIN_INSTALL: "plugin.install";
};
type FedCapability = (typeof FedCapability)[keyof typeof FedCapability];
/** Token issuance result: the raw token is shown/stored once by the receiver. */
interface IssuedToken {
  token: DeviceToken;
  tokenId: string;
  tokenHash: string;
}
/**
 * Mint a new device token. Returns the raw token exactly once; only the
 * SHA-256 hash is retained by the issuer (gateway compromise must not leak
 * reusable credentials — D-004 爆炸半径约束).
 */
declare function issueDeviceToken(deviceId: DeviceId): IssuedToken;
declare function hashToken(token: DeviceToken): string;
/** Constant-time token comparison over hashes (never over raw secrets). */
declare function tokenHashesEqual(a: string, b: string): boolean;
/** Narrow an untrusted string into a DeviceToken (format check only — lookup is separate). */
declare function asDeviceToken(value: unknown): DeviceToken | undefined;
/** Identity resolved server-side from the token store — never from client claims. */
interface DeviceIdentity {
  deviceId: DeviceId;
  displayName: string;
  caps: readonly FedCapability[];
  pairedAt: number;
}
/** Minimal token store contract the gateway (issuer side) implements. */
interface DeviceTokenStore {
  /** Resolve identity by raw token. Returns undefined for unknown/revoked tokens. */
  resolve(token: DeviceToken): DeviceIdentity | undefined;
}
/**
 * Authenticate an inbound request.
 *
 * The ONLY input consulted is the presented token; every other parameter is
 * diagnostic metadata for the audit log and cannot influence the decision.
 * This is the single choke point for the 禁止清单 rule on the gateway side.
 */
declare function authenticate(store: DeviceTokenStore, presented: unknown, context: {
  readonly source: string;
  readonly declaredName?: unknown;
}): {
  identity: DeviceIdentity;
} | {
  error: 'unauthenticated';
};
//#endregion
//#region src/errors.d.ts
/**
 * Structured federation error codes and error payloads.
 *
 * Error semantics are A-class benchmarked against dsh tool-call error structure:
 * a stable code discriminant plus human-readable detail, machine-usable fields
 * (retryAfterMs) kept separate from prose. Codes are security invariants —
 * fixed set, never configurable (AGENTS.md: protocol constants stay fixed).
 */
/** Stable wire error codes. Closed set: add only with a protocol version bump. */
declare const FedErrorCode: {
  /** connect protocol range does not overlap the peer's supported range. */
  readonly VERSION_MISMATCH: "version_mismatch";
  /** device token missing, unknown, revoked, or malformed. */
  readonly UNAUTHENTICATED: "unauthenticated";
  /** authenticated but the required capability was not granted at pairing. */
  readonly FORBIDDEN_CAPS: "forbidden_caps";
  /** request deadline elapsed before completion. */
  readonly DEADLINE_EXCEEDED: "deadline_exceeded";
  /** task cancelled by the initiator or an operator. */
  readonly CANCELLED: "cancelled";
  /** idempotencyKey replayed with a different payload fingerprint. */
  readonly IDEMPOTENCY_CONFLICT: "idempotency_conflict";
  /** receiver at queue capacity; retry after retryAfterMs. */
  readonly BUSY_RETRY_AFTER: "busy_retry_after";
  /** params failed wire-boundary validation. */
  readonly PAYLOAD_INVALID: "payload_invalid";
  /** method exists in the catalog but is not mounted on this peer. */
  readonly METHOD_NOT_MOUNTED: "method_not_mounted";
  /** method unknown to the peer. */
  readonly METHOD_UNKNOWN: "method_unknown";
  /** task referenced by id does not exist (or expired from the table). */
  readonly TASK_NOT_FOUND: "task_not_found";
  /** unexpected server-side failure; safe to retry with a new trace id. */
  readonly INTERNAL: "internal";
};
type FedErrorCode = (typeof FedErrorCode)[keyof typeof FedErrorCode];
/** Wire error payload carried by a failed `res` frame. */
interface FedError {
  code: FedErrorCode;
  message: string;
  /** Present only for BUSY_RETRY_AFTER: earliest safe retry time offset. */
  retryAfterMs?: number;
  /** Server-side trace id when the failure happened mid-pipeline. */
  traceId?: string;
}
declare function fedError(code: FedErrorCode, message: string, extra?: Omit<FedError, 'code' | 'message'>): FedError;
/** Narrow an unknown thrown value into a FedError for wire emission. */
declare function toFedError(value: unknown, traceId?: string): FedError;
//#endregion
//#region src/frames.d.ts
/** Wire protocol version of this implementation. Bump on breaking frame changes. */
declare const PROTOCOL_VERSION = 1;
/** Oldest wire protocol this build accepts. */
declare const MIN_PROTOCOL_VERSION = 1;
/** Newest wire protocol this build accepts. */
declare const MAX_PROTOCOL_VERSION = 1;
/** Connection roles. A host is a full agent runtime; a user is a chat surface. */
type PeerRole = 'gateway' | 'host' | 'user';
/** connect.req params — the first frame on any connection. */
interface ConnectParams {
  role: PeerRole;
  /** Human-readable device label; diagnostic only, never an identity source. */
  deviceName: string;
  protocol: {
    readonly min: number;
    readonly max: number;
  };
  /** Present on role:"host" only when presenting a pairing token or device token. */
  deviceToken?: string;
  /** Host capability advertisement; verified server-side, not trusted. */
  caps?: readonly FedCapability[];
}
/** connect res payload on success. */
interface HelloOk {
  protocol: number;
  peer: {
    role: PeerRole;
    deviceName: string;
  };
  /** Server wall clock so hosts can bound drift for deadline math. */
  serverTimeMs: number;
  /** Present when a host connected without a (valid) token: pairing is pending. */
  pairing?: {
    readonly code: string;
    readonly expiresAtMs: number;
  };
}
/** Request frame. */
interface FedRequest {
  readonly type: 'req';
  /** Correlation id; scopes the res frame. Never used for authorization. */
  readonly id: string;
  readonly method: string;
  readonly params: unknown;
  /** Absolute epoch ms after which the receiver should abort and reply DEADLINE_EXCEEDED. */
  readonly deadlineMs?: number;
  /** Required for side-effecting methods; replays with the same fingerprint resolve to the first result. */
  readonly idempotencyKey?: string;
  /** Pipeline trace id; generated by the initiator when absent. */
  readonly traceId?: string;
}
/** Response frame. */
interface FedResponse {
  readonly type: 'res';
  readonly id: string;
  readonly ok: boolean;
  readonly payload?: unknown;
  readonly error?: FedError;
}
/** Event frame; `seq` is per-connection monotonic and drives ack-based backpressure. */
interface FedEvent {
  readonly type: 'event';
  readonly event: string;
  readonly payload: unknown;
  readonly seq: number;
}
type FedFrame = FedRequest | FedResponse | FedEvent;
/** Event backpressure acknowledgement frame (transport-level, same wire). */
interface FedEventAck {
  readonly type: 'event.ack';
  /** Highest contiguous seq the receiver has durably processed. */
  readonly ackedThrough: number;
  /** Receiver asks the sender to slow down (credit-style backpressure hint). */
  readonly window: number;
}
type FedWireFrame = FedFrame | FedEventAck;
/** Parse and validate one untrusted wire frame. Throws FedError(PAYLOAD_INVALID). */
declare function decodeFrame(raw: unknown): FedWireFrame;
/**
 * Validate a connect handshake and negotiate the protocol version.
 * Rejects with VERSION_MISMATCH when the ranges do not overlap.
 */
declare function negotiateProtocol(params: ConnectParams): number;
/** Capabilities are always re-validated server-side; client lists are advertisements only. */
declare function sanitizeAdvertisedCaps(value: unknown): readonly FedCapability[];
//#endregion
//#region src/methods.d.ts
/**
 * Federation method and event catalogs.
 *
 * Naming is A-class benchmarked against dsh ctx.* service method conventions:
 * domain-prefixed, verb-last where a noun reads better, closed sets.
 * Side-effecting methods REQUIRE an idempotencyKey on the request frame.
 */
declare const FedMethod: {
  /** any peer → gateway: first frame on a connection (role + protocol range + token). */
  readonly CONNECT: "connect";
  /** host → gateway: present a pairing code, request a device token. */
  readonly PAIR_REQUEST: "pair.request";
  /** user surface → gateway: approve a pending pairing code. */
  readonly PAIR_APPROVE: "pair.approve";
  /** gateway → user surfaces: a pairing code awaits approval. */
  readonly PAIR_PENDING_EVENT: "pair.pending";
  /** host → gateway: advertise caps and current state summary (post-connect). */
  readonly HOST_REGISTER: "host.register";
  /** host → gateway: periodic state digest push (also available as an event). */
  readonly HOST_STATE_REPORT: "host.state.report";
  /** gateway → host: dispatch one directed task. Side-effecting. */
  readonly AGENT_TASK: "agent.task";
  /** gateway → host / host → gateway: cancel an in-flight task. Side-effecting. */
  readonly AGENT_TASK_CANCEL: "agent.task.cancel";
  /** gateway → host: ask a bounded introspection question (no side effects). */
  readonly AGENT_ASK: "agent.ask";
  /** user surface → gateway: send a chat turn. Side-effecting. */
  readonly CHAT_SEND: "chat.send";
  /** user surface → gateway: read synchronized session history (dsh session log mirror). */
  readonly CHAT_HISTORY: "chat.history";
  /** user surface → gateway: list paired hosts with their last state digests. */
  readonly HOST_LIST: "host.list";
};
type FedMethod = (typeof FedMethod)[keyof typeof FedMethod];
declare const FedEvent$1: {
  /** pairing outcome for the requesting host (approved token / denied reason). */
  readonly PAIR_RESULT: "pair/result";
  /** pairing code awaiting operator approval (gateway → user surfaces). */
  readonly PAIR_PENDING: "pair/pending";
  /** agent.stream — streamed agent output for a task/chat turn. */
  readonly AGENT_STREAM: "agent.stream";
  /** tool lifecycle mirrors (dsh tool/call, tool/result shape). */
  readonly TOOL_CALL: "tool/call";
  readonly TOOL_RESULT: "tool/result";
  /** host presence transitions (online/offline/busy). */
  readonly PRESENCE: "presence";
  /** task lifecycle updates (pending/running/done/failed/cancelled). */
  readonly TASK_UPDATED: "task/updated";
  /** host state digest broadcast. */
  readonly HOST_STATE: "host/state";
};
type FedEvent$1 = (typeof FedEvent$1)[keyof typeof FedEvent$1];
/** Methods whose req frames MUST carry idempotencyKey (security/consistency invariant). */
declare const IDEMPOTENT_METHODS: ReadonlySet<string>;
/** Task lifecycle states mirrored from dsh turn/step semantics. */
type TaskState = 'pending' | 'running' | 'done' | 'failed' | 'cancelled';
/** One directed task dispatch (gateway → host). */
interface AgentTaskParams {
  taskId: string;
  /** Instruction for the host agent. The host runs it under local approval. */
  prompt: string;
  /** Minimum caps the host must have been granted at pairing for this task. */
  requiredCaps: readonly string[];
  deadlineMs: number;
  traceId: string;
}
/** Bounded introspection question (gateway → host). */
interface AgentAskParams {
  questionId: string;
  prompt: string;
  deadlineMs: number;
  traceId: string;
}
/** Host state digest — the anti-信息差 payload injected into the main agent's context. */
interface HostStateDigest {
  deviceId: string;
  displayName: string;
  os: string;
  lanAddress: string;
  cpuLoadPct?: number;
  memTotalMb?: number;
  memFreeMb?: number;
  diskSummaries?: readonly {
    readonly mount: string;
    readonly freeMb: number;
  }[];
  reportedAtMs: number;
}
/** Side-effect methods must be dispatched with these delivery fields present. */
declare function requiresIdempotencyKey(method: string): boolean;
//#endregion
//#region src/index.d.ts
declare const name = "hive-fed-protocol";
/** Deployment-tunable config. Protocol/security constants are NOT here (AGENTS.md). */
interface Config {
  /** Reject connects whose negotiated version is not exactly this major line. Default true. */
  strictVersionCheck?: boolean;
}
/** The service exposed on `ctx` under the key `fedProtocol`. */
interface FedProtocolService {
  readonly version: {
    readonly current: number;
    readonly min: number;
    readonly max: number;
  };
  readonly methods: typeof FedMethod;
  readonly events: typeof FedEvent$1;
  readonly errorCodes: typeof FedErrorCode;
  /** Parse + validate one untrusted wire frame. Throws FedError(PAYLOAD_INVALID). */
  decodeFrame(raw: unknown): FedWireFrame;
  negotiateProtocol(params: ConnectParams): number;
  sanitizeAdvertisedCaps(value: unknown): readonly FedCapability[];
  requiresIdempotencyKey(method: string): boolean;
  /** Single authentication choke point (禁止清单 enforcement). */
  authenticate(store: DeviceTokenStore, presented: unknown, context: {
    readonly source: string;
    readonly declaredName?: unknown;
  }): {
    identity: DeviceIdentity;
  } | {
    error: 'unauthenticated';
  };
  issueDeviceToken(deviceId: DeviceId): IssuedToken;
  hashToken(token: DeviceToken): string;
  tokenHashesEqual(a: string, b: string): boolean;
  asDeviceToken(value: unknown): DeviceToken | undefined;
  fedError: typeof fedError;
  toFedError: typeof toFedError;
}
declare function apply(ctx: unknown, config?: Config): void;
//#endregion
export { type AgentAskParams, type AgentTaskParams, Config, type ConnectParams, type DeviceId, type DeviceIdentity, type DeviceToken, type DeviceTokenStore, FedCapability, type FedCapability as FedCapabilityType, type FedError, FedErrorCode, type FedEvent, type FedEventAck, FedEvent$1 as FedEventCatalog, type FedFrame, FedMethod, FedProtocolService, type FedRequest, type FedResponse, type FedWireFrame, type HelloOk, type HostStateDigest, IDEMPOTENT_METHODS, type IssuedToken, MAX_PROTOCOL_VERSION, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, type PeerRole, type TaskState, apply, asDeviceToken, authenticate, decodeFrame, fedError, hashToken, issueDeviceToken, name, negotiateProtocol, requiresIdempotencyKey, sanitizeAdvertisedCaps, toFedError, tokenHashesEqual };
//# sourceMappingURL=index.d.ts.map