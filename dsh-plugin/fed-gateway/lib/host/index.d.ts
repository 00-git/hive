import { GatewayConfig, GatewayServer } from "./server.js";
//#region src/index.d.ts
declare const name = "hive-fed-gateway";
/** Loader-layer config (cordis.patch.yml). The settings card layers on top. */
interface Config extends GatewayConfig {}
declare function apply(ctx: unknown, config?: Config): void;
//#endregion
export { Config, type GatewayConfig, GatewayServer, apply, name };
//# sourceMappingURL=index.d.ts.map