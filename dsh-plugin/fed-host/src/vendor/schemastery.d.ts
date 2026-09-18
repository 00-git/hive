/**
 * Minimal ambient typing for the vendored schemastery build (lib/index.mjs).
 * The full .d.ts lives upstream; the card code only touches object/number/
 * string schema builders plus the z<T> marker used by the settings contract.
 */
declare const z: {
  (schema: unknown): never
  object: (properties: Record<string, unknown>) => unknown
  number: () => unknown
  string: () => unknown
  infer: <T>(schema: unknown) => T
}
export default z
