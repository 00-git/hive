import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/server.ts', 'src/audit.ts', 'src/pairing.ts', 'src/registry.ts'],
  outDir: 'lib/host',
  format: 'esm',
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
})
