#!/usr/bin/env node
/**
 * hive-fedctl — minimal user-surface CLI for the federation gateway (MVP).
 * Pure JS. User token comes from ~/.hive/gateway-user-token (gateway writes it at boot).
 */
import WebSocket from 'ws'
import { readFileSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

const [cmd, ...rest] = process.argv.slice(2)
const gatewayUrl = process.env.HIVE_GATEWAY_URL ?? 'ws://127.0.0.1:3081/fed'
const tokenFile = join(homedir(), '.hive', 'gateway-user-token')

function readUserToken() {
  if (!existsSync(tokenFile)) {
    console.error(`user token file missing: ${tokenFile} (start the gateway first)`)
    process.exit(1)
  }
  return readFileSync(tokenFile, 'utf8').trim()
}

function connectUser() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(gatewayUrl)
    const timeout = setTimeout(() => reject(new Error('connect timeout')), 5000)
    ws.on('open', () => {
      clearTimeout(timeout)
      resolve(ws)
    })
    ws.on('error', (error) => {
      clearTimeout(timeout)
      reject(error)
    })
  })
}

function request(ws, id, method, params, extra = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.off('message', onMessage)
      reject(new Error(`request ${method} timed out`))
    }, 15_000)
    function onMessage(data) {
      const frame = JSON.parse(String(data))
      if (frame.type === 'event' && frame.event === 'pair/pending') {
        console.log(`[pairing pending] code ${frame.payload.code} for "${frame.payload.deviceName}"`)
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

const userToken = readUserToken()
const ws = await connectUser()
const id = `ctl-${randomBytes(4).toString('hex')}`
const hello = await request(ws, id, 'connect', {
  role: 'user',
  deviceName: 'fedctl',
  protocol: { min: 1, max: 1 },
  deviceToken: userToken,
})
console.log(`connected (protocol ${hello.protocol}) as user`)

async function readStdinAll() {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return chunks.join('').trim()
}

try {
  if (cmd === 'list') {
    const { hosts } = await request(ws, `id-${randomBytes(3).toString('hex')}`, 'host.list', {})
    if (hosts.length === 0) console.log('no paired hosts known')
    for (const host of hosts) {
      console.log(`${host.deviceId}  ${host.displayName}  os=${host.os}  memFree=${host.memFreeMb ?? '?'}MB`)
    }
  } else if (cmd === 'approve') {
    const code = rest[0]
    if (code === undefined) throw new Error('usage: approve <code>')
    const result = await request(ws, `id-${randomBytes(3).toString('hex')}`, 'pair.approve', { code })
    console.log(`approved: ${result.deviceId} (${result.deviceName}) caps=[${result.caps.join(', ')}]`)
  } else if (cmd === 'task') {
    const host = rest[0]
    let prompt = rest[1]
    if (host === undefined) throw new Error('usage: task <hostName> <jsonPrompt>  (or pipe the JSON prompt via stdin)')
    if (prompt === undefined) prompt = await readStdinAll()
    const result = await request(ws, `id-${randomBytes(3).toString('hex')}`, 'agent.task', { host, prompt }, { idempotencyKey: randomBytes(8).toString('hex') })
    console.log(JSON.stringify(result, null, 2))
    if (result && result.ok === false) process.exitCode = 1
  } else {
    console.log('usage: hive-fedctl <list | approve <code> | task <host> <jsonPrompt>>')
  }
} catch (error) {
  // Errors must reach the operator: print on stdout (stderr is dropped by
  // some console captures) and exit non-zero AFTER the write flushes.
  console.log(`error: ${error instanceof Error ? error.message : String(error)}`)
  ws.close()
  process.exit(1)
}
ws.close()
process.exit(0)
