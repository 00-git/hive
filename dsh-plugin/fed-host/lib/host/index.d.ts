import { n as HostConfig, t as HostClient } from "./client-TrDS4jMQ.js";
//#region src/index.d.ts
declare const name = "hive-fed-host";
interface Config extends HostConfig {}
declare function apply(ctx: unknown, config?: Config): void;
//#endregion
export { Config, HostClient, type HostConfig, apply, name };
//# sourceMappingURL=index.d.ts.map