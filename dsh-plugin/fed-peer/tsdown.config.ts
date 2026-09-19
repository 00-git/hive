import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  // Emit one level up from the other packages on purpose: the fed-protocol
  // import is a relative path, and '../../fed-protocol' only resolves to
  // dsh-plugin/fed-protocol from lib/ — not from lib/host/. Getting this wrong
  // produces a SECOND, structurally identical copy of the protocol types, and
  // branded ids from the two copies are not assignable to each other.
  outDir: 'lib',
  format: 'esm',
  platform: 'node',
  dts: true,
  sourcemap: true,
  clean: true,
  // The fed-protocol import is a relative path into its lib/ output, which is
  // only resolvable from src/. Inlining it (the default) is what makes the
  // emitted lib/host/index.js self-contained — same arrangement the gateway and
  // host packages already rely on.
  // Kept OUT of the bundle: inlining would duplicate the protocol's branded
  // types inside this package's .d.ts, and a DeviceId from here would then not
  // be assignable to one from fed-protocol.
  external: [/\/fed-protocol\//],
  outExtensions: () => ({ js: '.js', dts: '.d.ts' }),
})
