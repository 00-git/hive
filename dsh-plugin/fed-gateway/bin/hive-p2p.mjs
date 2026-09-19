#!/usr/bin/env node
/**
 * hive-p2p — OpenP2P orchestration for the hive federation.
 *
 * Why OpenP2P at all: hive nodes are on different networks, and OpenP2P
 * flattens them onto one private virtual network without exposing anything
 * publicly. hive does NOT depend on it for correctness — with no tunnel, peers
 * simply cannot reach each other, and the listener stays closed (fail-closed).
 *
 * This tool acquires the binary ITSELF (no manual download step), because the
 * operator should not have to know that a particular release asset name exists.
 *
 * Elevation, which is the one thing we cannot do for you: openp2p.exe declares
 * requireAdministrator (it installs a tunnel adapter), so Windows refuses to
 * launch it from an unelevated process. `fetch` places the binary and `run`
 * prints the exact command to execute once, as administrator. hive never
 * silently asks for elevation.
 *
 * Commands:
 *   hive-p2p fetch [--version vX.Y.Z] [--proxy URL] [--force]
 *   hive-p2p join  --node <节点名> [--user U] [--password P] [--peer <对端节点>] [--dst 3081] [--src 3082]
 *   hive-p2p run
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import { tmpdir } from 'node:os'

function argValue(flag) {
  const index = process.argv.indexOf(flag)
  return index >= 0 ? process.argv[index + 1] : undefined
}
function hasFlag(flag) {
  return process.argv.includes(flag)
}

const cmd = process.argv[2] ?? 'help'
const dir = argValue('--dir') ?? join(homedir(), '.hive', 'openp2p')
const configFile = argValue('--config') ?? join(dir, 'config.json')
const exeName = process.platform === 'win32' ? 'openp2p.exe' : 'openp2p'
const binPath = argValue('--bin') ?? join(dir, exeName)
const proxy = argValue('--proxy') ?? process.env.HIVE_PROXY ?? detectProxy()

/** Common local proxy ports, so the operator rarely has to pass one. */
function detectProxy() {
  return process.env.HTTPS_PROXY ?? process.env.https_proxy ?? 'http://127.0.0.1:7897'
}

function loadConfig() {
  if (!existsSync(configFile)) return undefined
  try {
    return JSON.parse(readFileSync(configFile, 'utf8'))
  } catch {
    return undefined
  }
}

function saveConfig(config) {
  mkdirSync(dir, { recursive: true })
  writeFileSync(configFile, JSON.stringify(config, null, 2), 'utf8')
}

// --- fetch -------------------------------------------------------------------

/**
 * Release asset naming is stable across versions: openp2p-<ver>.windows-amd64.zip.
 * Resolve the tag through the API rather than hardcoding a version, so `fetch`
 * keeps working as OpenP2P releases.
 */
async function resolveVersion() {
  const pinned = argValue('--version')
  if (pinned !== undefined) return pinned
  const response = await apiGet('https://api.github.com/repos/openp2p-cn/openp2p/releases/latest')
  const tag = JSON.parse(response)?.tag_name
  if (typeof tag !== 'string') throw new Error('could not read the latest release tag')
  return tag
}

function platformSuffix() {
  if (process.platform === 'win32') return process.arch === 'arm64' ? 'windows-arm64' : 'windows-amd64'
  if (process.platform === 'darwin') return process.arch === 'arm64' ? 'darwin-arm64' : 'darwin-amd64'
  return process.arch === 'arm64' ? 'linux-arm64' : 'linux-amd64'
}

/**
 * Fetch through the proxy first when one is configured.
 *
 * Node's global fetch has no proxy support of its own, so the fallback shells
 * out to the platform tool that does. Trying the direct path first matters for
 * machines that can already reach GitHub — the proxy is the exception there,
 * not the rule.
 */
async function httpGet(url, { binary = false } = {}) {
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'hive-p2p' } })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return binary ? Buffer.from(await response.arrayBuffer()) : await response.text()
  } catch (directError) {
    if (proxy === undefined || proxy.length === 0) throw directError
    const target = join(tmpdir(), `hive-p2p-${Date.now()}.zip`)
    const result = process.platform === 'win32'
      ? spawnSync('powershell', ['-NoProfile', '-Command',
          `Invoke-WebRequest -Uri '${url}' -OutFile '${target}' -Proxy '${proxy}' -TimeoutSec 180`], { stdio: 'inherit' })
      : spawnSync('curl', ['-fsSL', '--proxy', proxy, '-o', target, url], { stdio: 'inherit' })
    if (result.status !== 0) throw new Error(`download via proxy failed (exit ${result.status})`)
    const bytes = readFileSync(target)
    rmSync(target, { force: true })
    return binary ? bytes : bytes.toString('utf8')
  }
}

async function apiGet(url) {
  return httpGet(url)
}

async function fetchBinary() {
  if (existsSync(binPath) && !hasFlag('--force')) {
    console.log(`[hive-p2p] binary already present: ${binPath} (use --force to replace)`)
    return
  }
  const version = await resolveVersion()
  const asset = `openp2p-${version.replace(/^v/, '')}.${platformSuffix()}.${process.platform === 'win32' ? 'zip' : 'tar.gz'}`
  const url = `https://github.com/openp2p-cn/openp2p/releases/download/${version}/${asset}`
  console.log(`[hive-p2p] downloading ${asset}`)
  console.log(`[hive-p2p] proxy: ${proxy ?? '(none)'}`)

  mkdirSync(dir, { recursive: true })
  const archive = join(dir, asset)
  writeFileSync(archive, await httpGet(url, { binary: true }))

  if (process.platform === 'win32') {
    // Expand-Archive over a path we just wrote; no shell string interpolation
    // of operator input is involved.
    const result = spawnSync('powershell', ['-NoProfile', '-Command',
      `Expand-Archive -Path '${archive}' -DestinationPath '${dir}\\_x' -Force`], { stdio: 'inherit' })
    if (result.status !== 0) throw new Error('extract failed')
    const nested = join(dir, '_x', exeName)
    const source = existsSync(nested) ? nested : join(dir, '_x', `${exeName}.exe`)
    if (!existsSync(source)) throw new Error(`archive did not contain ${exeName}`)
    writeFileSync(binPath, readFileSync(source))
    rmSync(join(dir, '_x'), { recursive: true, force: true })
  } else {
    const result = spawnSync('tar', ['-xzf', archive, '-C', dir], { stdio: 'inherit' })
    if (result.status !== 0) throw new Error('extract failed')
  }
  rmSync(archive, { force: true })
  console.log(`[hive-p2p] binary ready: ${binPath}`)
  console.log('[hive-p2p] next: hive-p2p join --node <本机节点名>')
}

// --- join --------------------------------------------------------------------

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    const stdin = process.stdin
    process.stdout.write(question)
    // Suppress echo for the password specifically; the answer must not end up
    // in scrollback or a captured transcript.
    const onData = (char) => {
      const text = char.toString()
      if (text === '\n' || text === '\r' || text === '\u0004') {
        stdin.removeListener('data', onData)
        process.stdout.write('\n')
      } else {
        process.stdout.write('\u0008 \u0008')
      }
    }
    stdin.on('data', onData)
    rl.question('', (answer) => {
      stdin.removeListener('data', onData)
      rl.close()
      resolve(answer.trim())
    })
  })
}

function askVisible(question) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    rl.question(question, (answer) => {
      rl.close()
      resolve(answer.trim())
    })
  })
}

async function joinNetwork() {
  let node = argValue('--node')
  let user = argValue('--user')
  let password = argValue('--password')

  // Interactive when not supplied: the operator is present by definition (they
  // just ran this), so asking is friendlier than failing with a usage string.
  if (node === undefined) node = await askVisible('本机节点名 (便于识别，如 PC-2): ')
  if (user === undefined) user = await askVisible('OpenP2P 账号 (邮箱): ')
  if (password === undefined) password = await askHidden('OpenP2P 密码 (不回显): ')

  if (node.length === 0 || user.length === 0 || password.length === 0) {
    console.error('[hive-p2p] 节点名 / 账号 / 密码都不能为空')
    process.exit(1)
  }

  const previous = loadConfig()
  const config = previous ?? {
    network: { Node: node, User: user, Password: password, ShareBandwidth: 0, ServerHost: 'api.openp2p.cn', ServerPort: 27183 },
    apps: [],
  }
  config.network.Node = node
  config.network.User = user
  config.network.Password = password
  config.network.ShareBandwidth = 0 // 私有网络：不共享带宽、不进公共节点池

  const peer = argValue('--peer')
  if (peer !== undefined) {
    const dst = argValue('--dst') ?? '3081'
    const src = argValue('--src') ?? '3082'
    const entry = {
      AppName: `hive-${node}-to-${peer}`,
      Protocol: 'tcp',
      SrcPort: Number(src),
      PeerNode: peer,
      DstPort: Number(dst),
      DstHost: '127.0.0.1',
      Enabled: 1,
    }
    config.apps = (config.apps ?? []).filter((app) => app.AppName !== entry.AppName)
    config.apps.push(entry)
    console.log(`[hive-p2p] 已加转发: 本地 127.0.0.1:${src} -> ${peer}:${dst}`)
  }

  saveConfig(config)

  console.log('')
  console.log('[hive-p2p] 配置已写入: ' + configFile)
  console.log('')
  console.log('  ⚠ 请记住这组账号密码 —— 换机器/重装时要用同一个账号才能进同一张私有网：')
  console.log(`     节点名: ${node}`)
  console.log(`     账号:   ${user}`)
  console.log(`     密码:   ${password}`)
  console.log('')
  console.log('  下一步（需要管理员权限，hive 不会替你提权）:')
  console.log(`     右键「以管理员身份运行」终端，执行:`)
  console.log(`       "${binPath}" -d`)
  console.log('')
  console.log('  每台要互通的机器都要: fetch -> join -> 提权运行一次')
}

// --- run ---------------------------------------------------------------------

function run() {
  if (!existsSync(binPath)) {
    console.error(`[hive-p2p] 找不到二进制: ${binPath}`)
    console.error('[hive-p2p] 先执行: hive-p2p fetch')
    process.exit(1)
  }
  if (!existsSync(configFile)) {
    console.error(`[hive-p2p] 找不到配置: ${configFile}`)
    console.error('[hive-p2p] 先执行: hive-p2p join --node <本机节点名>')
    process.exit(1)
  }
  console.log(`[hive-p2p] 启动 ${binPath} (配置: ${configFile})`)
  const child = spawn(binPath, ['-d'], { cwd: dir, stdio: 'inherit' })
  child.on('error', (error) => {
    // The common failure here is Windows refusing an unelevated launch, which
    // is expected rather than a bug — say so instead of dumping an errno.
    if (String(error.message).includes('elevation')) {
      console.error('[hive-p2p] openp2p 需要管理员权限：请「以管理员身份运行」终端后再执行本命令')
    } else {
      console.error(`[hive-p2p] 启动失败: ${error.message}`)
    }
  })
  child.on('exit', (code) => process.exit(code ?? 0))
}

// --- dispatch ----------------------------------------------------------------

try {
  if (cmd === 'fetch') await fetchBinary()
  else if (cmd === 'join') await joinNetwork()
  else if (cmd === 'run') run()
  else {
    console.log([
      'usage:',
      '  hive-p2p fetch [--version vX.Y.Z] [--proxy URL] [--force]   下载 openp2p 二进制',
      '  hive-p2p join --node <节点名> [--user U] [--password P]      写入账号与私有网配置',
      '               [--peer <对端节点>] [--dst 3081] [--src 3082]',
      '  hive-p2p run                                                 启动隧道（需管理员）',
      '',
      '要点:',
      '  - 同一个账号 = 同一张私有网；ShareBandwidth=0 不进公共共享池',
      '  - 每台机器都要 fetch + join；要互通的对端各加一条 --peer 转发',
      '  - fed-host 的对端地址填 ws://127.0.0.1:<src>/fed',
      '  - 未入网电脑既看不到隧道端口，也无法访问联邦服务',
      '  - openp2p 需要管理员权限，hive 不会替你提权',
    ].join('\n'))
  }
} catch (error) {
  // Errors must reach the operator on stdout: some console captures drop stderr.
  console.log(`[hive-p2p] error: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
}
