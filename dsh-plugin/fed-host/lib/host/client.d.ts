//#region src/client.d.ts
interface HostConfig {
  gatewayUrl?: string;
  deviceName?: string;
  /** Directory for the stored device token + audit log (defaults to ~/.hive). */
  stateDir?: string;
  /** Directories fs.read may touch. Defaults to [process.cwd()]. */
  whitelistDirs?: readonly string[];
  stateIntervalMs?: number;
}
declare class HostClient {
  #private;
  constructor(config?: HostConfig);
  start(): void;
  stop(): void;
}
//#endregion
export { HostClient, HostConfig };
//# sourceMappingURL=client.d.ts.map