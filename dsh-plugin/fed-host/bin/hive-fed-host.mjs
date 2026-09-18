#!/usr/bin/env node
/**
 * Standalone host runner (plain JS, no dsh required).
 * Usage: node bin/hive-fed-host.mjs [--name PC-2] [--gateway ws://host:3081/fed] [--allow-dir PATH]
 */
import { HostClient } from '../lib/host/index.js'

function argValue(flag) {
  const index = process.argv.indexOf(flag)
  return index >= 0 ? process.argv[index + 1] : undefined
}

const client = new HostClient({
  gatewayUrl: argValue('--gateway'),
  deviceName: argValue('--name'),
  stateDir: argValue('--state-dir'),
  whitelistDirs: argValue('--allow-dir') !== undefined ? [argValue('--allow-dir')] : undefined,
})

client.start()
console.log('[hive-fed-host] standalone runner started; Ctrl+C to stop')

process.on('SIGINT', () => {
  client.stop()
  process.exit(0)
})
