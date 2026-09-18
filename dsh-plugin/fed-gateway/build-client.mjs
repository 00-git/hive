/**
 * Builds the browser half into dsh's closure-factory artifact:
 *   window.__ModuleLoader__.load({ id, factory: (require) => { ...CJS bundle... } })
 * Externals (react, @deepseek-ai/*) resolve through the loader's injected
 * require at runtime — mirroring the model-proxy reference bundle.
 */
import { build } from 'esbuild'

await build({
  entryPoints: ['src/client/index.tsx'],
  outfile: 'lib/client.js',
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  jsx: 'automatic',
  sourcemap: true,
  legalComments: 'none',
  external: [
    'react',
    'react/jsx-runtime',
    'react-dom',
    'react-dom/client',
    '@deepseek-ai/cordis',
    '@deepseek-ai/dsh-client-connection',
    '@deepseek-ai/dsh-client-locale',
    '@deepseek-ai/dsh-client-ui-renderer',
    '@deepseek-ai/dsh-client-ui-settings',
    '@deepseek-ai/dsh-client-ui-slots',
    '@deepseek-ai/dsh-client-store',
    '@deepseek-ai/dsh-api-remotes',
  ],
  banner: {
    js: 'window.__ModuleLoader__.load({ id: "hive-fed-gateway", factory: (require) => {\nvar module = { exports: {} }; var exports = module.exports;',
  },
  footer: {
    js: '\nreturn module.exports; } });',
  },
})
console.log('client bundle written to lib/client.js')
