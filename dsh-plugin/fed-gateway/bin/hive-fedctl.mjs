#!/usr/bin/env node
/**
 * hive-fedctl — the local operator surface for a hive node.
 *
 * Two families of command, with deliberately different plumbing:
 *
 *   trust …   reads and writes ~/.hive/trusted-peers.json DIRECTLY.
 *             Trust is a local decision and that file is the shared medium, so
 *             these work with dsh stopped — which matters, because approving a
 *             peer is exactly the moment you may not have a working node yet.
 *
 *   peers/task  talk to the local listener over WS with the loopback operator
 *             token. These need the node running, because they act on live
 *             connections rather than on recorded decisions.
 *
 * The trust logic itself is NOT reimplemented here: it is imported from the
 * protocol/peer packages so the SAS comparison has exactly one implementation.
 * Only the file I/O glue is local, since this script must run without a build.
 */
import WebSocket from 'ws'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

const stateDir = process.env.HIVE_STATE_DIR ?? join(homedir(), '.hive')
const trustFile = join(stateDir, 'trusted-peers.json')
const gatewayUrl = process.env.HIVE_GATEWAY_URL ?? 'ws://127.0.0.1:3081/fed'
const tokenFile = join(stateDir, 'gateway-user-token')

const [cmd, sub, ...rest] = process.argv.slice(2)

// --- module resolution -------------------------------------------------------

/**
 * Find the protocol package in whichever layout we are running from.
 *
 * Installed via `pnpm add file:` the packages land in node_modules and the
 * package name resolves; run straight out of the repository the relative paths
 * do. Trying both is what keeps this script working in either place — a single
 * relative path silently breaks one of them.
 */
async function loadProtocol() {
  const candidates = ['hive-fed-protocol', '../../fed-peer/lib/index.js', '../../fed-protocol/lib/host/index.js']
  const failures = []
  for (const candidate of candidates) {
    try {
      return await import(candidate)
    } catch (error) {
      failures.push(`${candidate}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  console.error('无法加载 hive 协议包，试过:')
  for (const failure of failures) console.error(`  - ${failure}`)
  console.error('提示: 在 dsh 的 profile 目录里 `pnpm add file:<仓库>/dsh-plugin/fed-protocol`')
  process.exit(1)
}

/**
 * The shared trust document, read and written as-is.
 *
 * Written through a temp file + rename so a crash mid-write cannot leave a
 * truncated table behind — losing the operator's decisions to a partial write
 * would mean re-confirming every peer by hand.
 */
function trustPersistence() {
  return {
    load: () => {
      if (!existsSync(trustFile)) return undefined
      try {
        const parsed = JSON.parse(readFileSync(trustFile, 'utf8'))
        if (Array.isArray(parsed)) return { trusted: parsed, pending: [] }
        if (typeof parsed !== 'object' || parsed === null) return undefined
        return {
          trusted: Array.isArray(parsed.trusted) ? parsed.trusted : [],
          pending: Array.isArray(parsed.pending) ? parsed.pending : [],
        }
      } catch {
        return undefined
      }
    },
    save: (snapshot) => {
      mkdirSync(stateDir, { recursive: true })
      const temp = `${trustFile}.tmp`
      writeFileSync(temp, JSON.stringify(snapshot, null, 2), 'utf8')
      renameSync(temp, trustFile)
    },
  }
}

// --- ws ----------------------------------------------------------------------

function readOperatorToken() {
  if (!existsSync(tokenFile)) {
    console.error(`找不到本机操作员令牌: ${tokenFile}`)
    console.error('说明本机监听还没起来过（先启动 dsh，或让插件加载一次）')
    process.exit(1)
  }
  return readFileSync(tokenFile, 'utf8').trim()
}

function connectOperator() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(gatewayUrl)
    const timer = setTimeout(() => reject(new Error(`连接超时: ${gatewayUrl}`)), 5000)
    ws.on('open', () => { clearTimeout(timer); resolve(ws) })
    ws.on('error', (error) => { clearTimeout(timer); reject(error) })
  })
}

/** One request/response exchange, with pairing-related events surfaced live. */
function request(ws, id, method, params, extra = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.off('message', onMessage)
      reject(new Error(`${method} 超时`))
    }, 20_000)
    function onMessage(data) {
      const frame = JSON.parse(String(data))
      if (frame.type === 'event' && frame.event === 'trust/pending') {
        console.log(`[待确认] ${frame.payload.nickname} (${frame.payload.deviceId})  SAS ${frame.payload.sas}`)
        return
      }
      if (frame.type === 'res' && frame.id === id) {
        clearTimeout(timer)
        ws.off('message', onMessage)
        if (frame.ok) resolve(frame.payload)
        else reject(new Error(`${frame.error.code}: ${frame.error.message}`))
      }
    }
    ws.on('message', onMessage)
    ws.send(JSON.stringify({ type: 'req', id, method, params, ...extra, traceId: `ctl-${Date.now()}` }))
  })
}

/** Open an operator session, or explain precisely why it could not. */
async function operatorSession(protocol) {
  const ws = await connectOperator()
  const hello = await request(ws, `ctl-${randomBytes(4).toString('hex')}`, protocol.FedMethod.CONNECT, {
    role: 'user',
    protocol: { min: protocol.MIN_PROTOCOL_VERSION, max: protocol.MAX_PROTOCOL_VERSION },
    userToken: readOperatorToken(),
  })
  return { ws, hello }
}

// --- commands ----------------------------------------------------------------

async function trustCommand(protocol) {
  const table = new protocol.TrustTable(trustPersistence(), undefined)
  const pad = (value, width) => String(value).padEnd(width)

  if (sub === undefined || sub === 'list') {
    const peers = table.list()
    if (peers.length === 0) {
      console.log('还没有已确认的对端。用 `hive-fedctl trust pending` 看待确认的。')
      return
    }
    console.log(`${pad('设备ID', 18)}${pad('昵称', 20)}${pad('能力', 28)}确认时间`)
    for (const peer of peers) {
      console.log(`${pad(peer.deviceId, 18)}${pad(peer.displayName || '(无)', 20)}${pad(peer.caps.join(','), 28)}${new Date(peer.trustedAtMs).toLocaleString()}`)
    }
    return
  }

  if (sub === 'pending') {
    const pending = table.pending()
    if (pending.length === 0) {
      console.log('没有待确认的对端。')
      return
    }
    console.log('待确认（请在【另一台机器】屏幕上核对同样的 6 位数字）:')
    for (const item of pending) {
      console.log('')
      console.log(`  设备ID : ${item.deviceId}`)
      console.log(`  昵称   : ${item.nickname}`)
      console.log(`  ← 本机 SAS: ${item.sas}`)
      console.log(`  确认命令: hive-fedctl trust approve ${item.deviceId} <对端屏幕上显示的数字>`)
    }
    console.log('')
    console.log('两个数字一样时它们本来就相同；不一样就是中间人的特征，请停下来，不要重试。')
    return
  }

  if (sub === 'approve') {
    const deviceId = rest[0]
    const sas = rest[1] ?? process.argv[process.argv.indexOf('--sas') + 1]
    if (deviceId === undefined || sas === undefined) {
      console.error('用法: hive-fedctl trust approve <设备ID> <SAS> [--as <昵称>]')
      console.error('      SAS 必须是【另一台机器】屏幕上显示的数字')
      process.exit(1)
    }
    const index = process.argv.indexOf('--as')
    const nickname = index >= 0 ? process.argv[index + 1] : undefined
    const result = table.approve(deviceId, sas, nickname === undefined ? undefined : { nickname })
    if (!result.ok) {
      console.error(`拒绝: ${result.reason}`)
      if (result.reason === 'sas_mismatch') {
        console.error('数字对不上 —— 这正是中间人的特征。请停下来核对两台机器的屏幕，不要换个数字再试。')
      }
      process.exit(1)
    }
    console.log(`已确认: ${result.peer.deviceId} (${result.peer.displayName})`)
    console.log('该对端会在几秒内被本机监听提升为可用连接（无需重启）。')
    return
  }

  if (sub === 'revoke') {
    const deviceId = rest[0]
    if (deviceId === undefined) {
      console.error('用法: hive-fedctl trust revoke <设备ID>')
      process.exit(1)
    }
    console.log(table.revoke(deviceId) ? `已撤销: ${deviceId}` : `没有找到: ${deviceId}`)
    return
  }

  if (sub === 'identity') {
    const identity = protocol.generateIdentity
    void identity
    // The node's own id lives beside the trust table; read it rather than
    // minting a new one, which would silently change who this machine is.
    const identityFile = join(stateDir, 'identity.json')
    if (!existsSync(identityFile)) {
      console.error('本机还没有身份（先启动一次 dsh，让插件生成）')
      process.exit(1)
    }
    const parsed = JSON.parse(readFileSync(identityFile, 'utf8'))
    console.log(`本机设备ID: ${parsed.deviceId}`)
    console.log(`公钥      : ${parsed.publicKey}`)
    return
  }

  console.error('用法: hive-fedctl trust <list|pending|approve|revoke|identity>')
  process.exit(1)
}

async function peerCommand(protocol) {
  const { ws } = await operatorSession(protocol)
  try {
    if (cmd === 'peers') {
      const { peers } = await request(ws, `id-${randomBytes(3).toString('hex')}`, protocol.FedMethod.HOST_LIST, {})
      if (peers.length === 0) {
        console.log('还没有已配对且在线过的对端。')
        return
      }
      for (const peer of peers) {
        const mark = peer.online ? '●' : '○'
        console.log(`${mark} ${peer.nickname || '(无昵称)'} [${peer.deviceId}]  os=${peer.os}  空闲内存=${peer.memFreeMb ?? '?'}MB`)
      }
      return
    }
    if (cmd === 'task') {
      const peer = sub
      let prompt = rest[0]
      if (peer === undefined) {
        console.error('用法: hive-fedctl task <昵称|设备ID> <JSON提示词>   (或把提示词管道进来)')
        process.exit(1)
      }
      if (prompt === undefined) {
        const chunks = []
        for await (const chunk of process.stdin) chunks.push(chunk)
        prompt = chunks.join('').trim()
      }
      const result = await request(ws, `id-${randomBytes(3).toString('hex')}`, protocol.FedMethod.AGENT_TASK, { peer, prompt }, { idempotencyKey: randomBytes(8).toString('hex') })
      console.log(JSON.stringify(result, null, 2))
      if (result && result.ok === false) process.exitCode = 1
      return
    }
    console.error('用法: hive-fedctl <peers | task <对端> <JSON>>')
    process.exit(1)
  } finally {
    ws.close()
  }
}

function help() {
  console.log([
    'hive-fedctl — 本机操作面',
    '',
    '信任（本地决策，dsh 没开也能用）:',
    '  trust list                              已确认的对端',
    '  trust pending                           待确认的对端（含本机 SAS）',
    '  trust approve <设备ID> <SAS> [--as 昵称]  确认对端（SAS 取【对端屏幕】上的数字）',
    '  trust revoke <设备ID>                    撤销对端（立即生效）',
    '  trust identity                          打印本机设备ID与公钥',
    '',
    '实况（需要本机监听在跑）:',
    '  peers                                   已配对对端及其状态',
    '  task <昵称|设备ID> <JSON提示词>           派任务，例如 \'{"op":"sysinfo"}\'',
    '',
    '环境变量: HIVE_STATE_DIR（状态目录）、HIVE_GATEWAY_URL（本机监听地址）',
  ].join('\n'))
}

// --- dispatch ----------------------------------------------------------------

try {
  if (cmd === 'trust') {
    await trustCommand(await loadProtocol())
  } else if (cmd === 'peers' || cmd === 'task') {
    await peerCommand(await loadProtocol())
  } else {
    help()
  }
} catch (error) {
  // Errors must reach the operator on stdout: some console captures drop stderr.
  console.log(`error: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
}
