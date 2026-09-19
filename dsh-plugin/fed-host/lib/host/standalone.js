import { t as HostClient } from "./client-BmPB8yBL.js";
//#region src/standalone.ts
/**
* Standalone host runner source (built to lib/host/standalone.js, wrapped by bin/hive-fed-host.mjs).
*/
function runStandalone(config) {
	const client = new HostClient(config);
	client.start();
	console.log("[hive-fed-host] standalone runner started; Ctrl+C to stop");
	process.on("SIGINT", () => {
		client.stop();
		process.exit(0);
	});
	return client;
}
if (process.argv[1] !== void 0 && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/").split("/").pop() ?? "?")) {
	function argValue(flag) {
		const index = process.argv.indexOf(flag);
		return index >= 0 ? process.argv[index + 1] : void 0;
	}
	runStandalone({
		peerUrls: process.argv.flatMap((arg, index) => arg === "--peer" || arg === "--peers" ? (process.argv[index + 1] ?? "").split(",").filter((url) => url.length > 0) : []),
		nickname: argValue("--name"),
		stateDir: argValue("--state-dir"),
		whitelistDirs: argValue("--allow-dir") !== void 0 ? [argValue("--allow-dir")] : void 0
	});
}
//#endregion
export { runStandalone };

//# sourceMappingURL=standalone.js.map