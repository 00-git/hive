#!/usr/bin/env node
/**
 * hive-p2p — OpenP2P orchestrator for the hive federation (MVP).
 * Pure JS. Generates an OpenP2P config.json that tunnels the federation WS
 * through the P2P network, so hosts on any network reach the gateway without
 * exposing it publicly:
 *
 *   gateway machine:  hive-p2p init --node HIVE-GW --token <NETTOKEN> --serve 3081
 *                     hive-p2p run
 *   each PC:          hive-p2p init --node PC-3 --token <NETTOKEN> --peer HIVE-GW --dst 3081 --src 3082
 *                     hive-p2p run
 *                     (fed-host gatewayUrl becomes ws://127.0.0.1:3082/fed — 配置在设置卡里改)
 *
 * The openp2p binary is NOT auto-downloaded: put it at --bin (default
 * ~/.hive/openp2p/openp2p.exe) — download from openp2p.cn or GitHub releases.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'

function argValue(flag) {
  const index = process.argv.indexOf(flag)
  return index >= 0 ? process.argv[index + 1] : undefined
}

const cmd = process.argv[2] ?? 'help'
const dir = argValue('--dir') ?? join(homedir(), '.hive', 'openp2p')
const configFile = join(dir, 'config.json')
const defaultBin = process.platform === 'win32' ? join(dir, 'openp2p.exe') : join(dir, 'openp2p')
const binPath = argValue('--bin') ?? defaultBin

function loadExisting() {
  if (!existsSync(configFile)) return undefined
  try {
    return JSON.parse(readFileSync(configFile, 'utf8'))
  } catch {
    return undefined
  }
}

if (cmd === 'init') {
  const node = argValue('--node')
  const token = argValue('--token')
  if (node === undefined || token === undefined) {
    console.error('usage: hive-p2p init --node <节点名> --token <网络Token> [--serve 3081 | --peer <网关节点名> --dst 3081 --src 3082]')
    process.exit(1)
  }
  const previous = loadExisting()
  const config = previous ?? {
    network: { Node: node, Token: token, ShareBandwidth: 0, ServerHost: 'api.openp2p.cn', ServerPort: 27183 },
    apps: [],
  }
  config.network.Node = node
  config.network.Token = token
  config.network.ShareBandwidth = 0 // 私有网络：不共享带宽、不进公共节点池
  const serve = argValue('--serve')
  const peer = argValue('--peer')
  if (serve !== undefined) {
    // Gateway side: expose the federation WS to authorized peers only.
    // OpenP2P apps are pull-based: the PEER adds the forward entry pointing at
    // this node; the gateway itself needs no app row (SDWAN/直连覆盖) — kept
    // here as documentation of the exposed service.
    console.log(`[hive-p2p] gateway node "${node}" will serve federation port ${serve} to paired peers`)
  }
  if (peer !== undefined) {
    const dst = argValue('--dst') ?? '3081'
    const src = argValue('--src') ?? '3082'
    const entry = {
      AppName: `hive-${node}`,
      Protocol: 'tcp',
      SrcPort: Number(src),
      PeerNode: peer,
      DstPort: Number(dst),
      DstHost: '127.0.0.1',
      Enabled: 1,
    }
    config.apps = (config.apps ?? []).filter((app) => app.AppName !== entry.AppName)
    config.apps.push(entry)
    console.log(`[hive-p2p] forward: local 127.0.0.1:${src} -> ${peer}:${dst} (P2P 隧道, 仅同网络成员可达)`)
  }
  mkdirSync(dir, { recursive: true })
  writeFileSync(configFile, JSON.stringify(config, null, 2), 'utf8')
  console.log(`[hive-p2p] config written: ${configFile}`)
  console.log('[hive-p2p] next: place the openp2p binary, then run: hive-p2p run')
  process.exit(0)
}

if (cmd === 'run') {
  if (!existsSync(binPath)) {
    console.error(`openp2p binary not found: ${binPath}`)
    console.error('download it manually (本机网络限制无法自动下载):')
    console.error('  - https://www.openp2p.cn/  (官网/控制台)')
    console.error('  - https://github.com/openp2p-cn/OpenP2P/releases')
    console.error(`then place it at ${binPath} and re-run: hive-p2p run`)
    process.exit(1)
  }
  console.log(`[hive-p2p] starting ${binPath} (config: ${configFile})`)
  const child = spawn(binPath, ['-d'], { cwd: dir, stdio: 'inherit' })
  child.on('exit', (code) => process.exit(code ?? 0))
} else if (cmd === 'help' || cmd === undefined) {
  console.log([
    'usage:',
    '  hive-p2p init --node <节点名> --token <网络Token> --serve 3081        # 网关侧',
    '  hive-p2p init --node <节点名> --token <网络Token> --peer <网关节点> --dst 3081 --src 3082  # PC 侧',
    '  hive-p2p run [--bin <openp2p 路径>]',
    '',
    '要点:',
    '  - 同一 --token = 同一私有 P2P 网络；ShareBandwidth=0 不进公共共享池',
    '  - PC 侧生成的是「本地转发」：fed-host 的网关地址改填 ws://127.0.0.1:<src>/fed',
    '  - 未入网电脑既看不到隧道端口，也无法访问模型与联邦服务',
  ].join('\n'))
  process.exit(0)
} else {
  console.error(`unknown command: ${cmd} (try: help)`)
  process.exit(1)
}
