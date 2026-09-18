import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
//#region src/audit.ts
/**
* JSONL audit for host-side permission decisions (安全模型第 4 条：host 侧双写).
*/
var AuditLog = class {
	#file;
	constructor(file) {
		this.#file = file;
		if (file !== void 0) mkdirSync(dirname(file), { recursive: true });
	}
	write(entry) {
		const line = JSON.stringify(entry);
		if (this.#file !== void 0) try {
			appendFileSync(this.#file, `${line}\n`, "utf8");
		} catch {}
		console.log(`[hive-host-audit] ${line}`);
	}
};
//#endregion
export { AuditLog };

//# sourceMappingURL=audit.js.map