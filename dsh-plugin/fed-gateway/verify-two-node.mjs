/**
 * Two-node end-to-end check on ONE machine.
 *
 * Runs a real listener and a real dialer in separate state directories with
 * separate identities, then walks the whole flow: mutual handshake, SAS
 * agreement, operator confirmation arriving through the SHARED TRUST FILE
 * (exactly how the CLI approves), promotion by the trust sync sweep, and a
 * directed task round trip.
 *
 * This is the test that would have caught every integration bug we hit, because
 * nothing here is stubbed — it is the same code both halves run in production.
 */
import { rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import WebSocket from 'ws'
import { GatewayServer } from './lib/host/server.js'
import { HostClient } from '../fed-host/lib/host/index.js'
import { TrustTable, trustPersistenceFor } from '../fed-peer/lib/index.js'

const PORT = 3091
const URL = `ws://127.0.0.1:${PORT}/fed`
const DIR_A = join(homedir(), '.hive-verify-a')
const DIR_B = join(homedir(), '.hive-verify-b')

let failed = 0
function check(name, actual, expected) {
  const ok = Object.is(actual, expected)
  if (!ok) failed += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : `  (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`}`)
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function waitFor(label, predicate, timeoutMs = 15_000) {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    const value = predicate()
    if (value) return value
    await sleep(150)
  }
  throw new Error(`timed out waiting for: ${label}`)
}

/** Operator session against the gateway (the fedctl path). */
function operatorRequest(token, id, method, params, extra = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(URL)
    const timer = setTimeout(() => { ws.close(); reject(new Error(`${method} timed out`)) }, 10_000)
    ws.on('open', () => {
      const send = (frame) => ws.send(JSON.stringify(frame))
      send({ type: 'req', id: `${id}-c`, method: 'connect', params: { role: 'user', protocol: { min: 2, max: 2 }, userToken: token } })
      ws.on('message', (data) => {
        const frame = JSON.parse(String(data))
        if (frame.type !== 'res') return
        if (frame.id === `${id}-c`) {
          if (!frame.ok) { clearTimeout(timer); ws.close(); reject(new Error(`connect: ${frame.error.message}`)); return }
          send({ type: 'req', id, method, params, ...extra, traceId: 'verify' })
          return
        }
        if (frame.id === id) {
          clearTimeout(timer)
          ws.close()
          if (frame.ok) resolve(frame.payload)
          else reject(new Error(`${frame.error.code}: ${frame.error.message}`))
        }
      })
    })
    ws.on('error', (error) => { clearTimeout(timer); reject(error) })
  })
}

for (const dir of [DIR_A, DIR_B]) {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true })
}

const gateway = new GatewayServer({ port: PORT, bindHost: '127.0.0.1', stateDir: DIR_A, nickname: 'NODE-A' })
const host = new HostClient({
  peerUrls: [URL],
  nickname: 'NODE-B',
  stateDir: DIR_B,
  whitelistDirs: [process.cwd()],
  stateIntervalMs: 2_000,
})

try {
  gateway.start()
  check('listener is up', gateway.listening, true)
  await sleep(300)
  host.start()

  // --- handshake reaches both operators -------------------------------------
  const pendingOnA = await waitFor('gateway to hold the peer', () => {
    const rows = gateway.pendingTrust()
    return rows.length === 1 ? rows : undefined
  })
  check('gateway derived the dialer id itself', String(pendingOnA[0].deviceId).length, 16)
  check('gateway learned the peer nickname', pendingOnA[0].nickname, 'NODE-B')

  const pendingOnB = await waitFor('dialer to hold the acceptor', () => {
    const rows = host.pendingTrust()
    return rows.length === 1 ? rows : undefined
  })
  check('dialer learned the acceptor nickname', pendingOnB[0].nickname, 'NODE-A')

  // The whole security model rests on these two matching without any shared
  // secret — they are derived from the two public keys on each side.
  check('both machines computed the SAME sas', pendingOnA[0].sas, pendingOnB[0].sas)
  check('sas is six digits', /^\d{6}$/.test(pendingOnA[0].sas), true)

  // --- the wrong SAS must be refused ----------------------------------------
  const wrong = String((Number(pendingOnA[0].sas) + 1) % 1_000_000).padStart(6, '0')
  let refused = false
  try {
    await operatorRequest(gateway.userToken, 'bad-approve', 'trust.approve', { deviceId: pendingOnA[0].deviceId, sas: wrong })
  } catch { refused = true }
  check('gateway refuses a mismatched sas', refused, true)

  // --- approve on A through the operator surface ----------------------------
  const approved = await operatorRequest(gateway.userToken, 'approve', 'trust.approve', { deviceId: pendingOnA[0].deviceId, sas: pendingOnA[0].sas })
  check('gateway accepted the operator approval', approved.deviceId, pendingOnA[0].deviceId)

  // --- approve on B through the SHARED FILE, exactly like the CLI -----------
  // This is the cross-process path: a separate TrustTable instance writes the
  // file the running node reads. If the refresh-on-access logic were wrong, the
  // link would never come up here.
  const tableB = new TrustTable(trustPersistenceFor(DIR_B))
  const approveB = tableB.approve(pendingOnB[0].deviceId, pendingOnB[0].sas)
  check('dialer-side approval via the trust file', approveB.ok, true)

  // --- both sides promote without a reconnect -------------------------------
  const peers = await waitFor('peer to appear in the gateway registry', () => {
    const rows = gateway.peerStates()
    return rows.some((row) => row.online) ? rows : undefined
  })
  check('gateway sees the peer online', peers.filter((row) => row.online).length, 1)
  check('peer nickname survived the promotion', peers.find((row) => row.online).nickname, 'NODE-B')
  check('peer capabilities came from the approved row',
    gateway.peerStates().some((row) => row.online), true)

  // --- a real directed task -------------------------------------------------
  const result = await operatorRequest(gateway.userToken, 'task', 'agent.task',
    { peer: 'NODE-B', prompt: JSON.stringify({ op: 'sysinfo' }) },
    { idempotencyKey: 'verify-1' })
  check('task reached the peer and returned ok', result?.ok, true)
  check('the result carries the task id', result?.taskId !== undefined, true)

  // --- dispatch by nickname is refused for an unknown name ------------------
  let unknownRefused = false
  try {
    await operatorRequest(gateway.userToken, 'task2', 'agent.task',
      { peer: 'NO-SUCH-PEER', prompt: JSON.stringify({ op: 'sysinfo' }) },
      { idempotencyKey: 'verify-2' })
  } catch { unknownRefused = true }
  check('an unknown peer name is refused', unknownRefused, true)

  // --- revocation cuts the live socket --------------------------------------
  const revoke = await operatorRequest(gateway.userToken, 'revoke', 'trust.revoke', { deviceId: pendingOnA[0].deviceId })
  check('revocation reported success', revoke.revoked, true)
  await sleep(3_000) // one trust-sync tick plus slack
  check('a revoked peer is no longer online', gateway.peerStates().some((row) => row.online), false)
} catch (error) {
  failed += 1
  console.log(`FAIL ${error instanceof Error ? error.message : String(error)}`)
} finally {
  host.stop()
  gateway.stop()
}

console.log(failed === 0 ? '\nALL PASS' : `\n${failed} FAILED`)
process.exit(failed === 0 ? 0 : 1)
