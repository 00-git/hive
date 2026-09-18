import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'lib/host',
  format: 'esm',
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  // Emit .js/.d.ts to match the package.json exports contract
  // (same layout as the model-proxy reference plugin: lib/host/index.js).
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
})
