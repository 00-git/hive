/**
 * Standalone host runner source (built to lib/host/standalone.js, wrapped by bin/hive-fed-host.mjs).
 */
import { HostClient } from './client.js'

export function runStandalone(config: import('./client.js').HostConfig): HostClient {
  const client = new HostClient(config)
  client.start()
  console.log('[hive-fed-host] standalone runner started; Ctrl+C to stop')
  process.on('SIGINT', () => {
    client.stop()
    process.exit(0)
  })
  return client
}

// Direct execution: node lib/host/standalone.js
if (process.argv[1] !== undefined && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop() ?? '?')) {
  function argValue(flag: string): string | undefined {
    const index = process.argv.indexOf(flag)
    return index >= 0 ? process.argv[index + 1] : undefined
  }
  runStandalone({
    // Repeatable --peer, or one --peers with a comma-separated list.
    peerUrls: process.argv.flatMap((arg, index) =>
      arg === '--peer' || arg === '--peers' ? (process.argv[index + 1] ?? '').split(',').filter((url) => url.length > 0) : []
    ),
    nickname: argValue('--name'),
    stateDir: argValue('--state-dir'),
    whitelistDirs: argValue('--allow-dir') !== undefined ? [argValue('--allow-dir') as string] : undefined,
  })
}
