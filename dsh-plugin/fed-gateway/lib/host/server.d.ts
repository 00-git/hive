//#region src/server.d.ts
interface GatewayConfig {
  port?: number;
  bindHost?: string;
  auditPath?: string;
  /** Directory for the gateway user token file (defaults to ~/.hive). */
  stateDir?: string;
}
declare class GatewayServer {
  #private;
  constructor(config?: GatewayConfig);
  get userToken(): string;
  start(): void;
  stop(): void;
}
//#endregion
export { GatewayConfig, GatewayServer };
//# sourceMappingURL=server.d.ts.map