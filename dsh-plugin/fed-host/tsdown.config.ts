import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts', 'src/client.ts', 'src/ops.ts', 'src/audit.ts', 'src/standalone.ts'],
  outDir: 'lib/host',
  format: 'esm',
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
})
