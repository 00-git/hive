import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
//#region src/audit.ts
/**
* JSONL audit log — every cross-trust-boundary decision lands here.
* 安全模型第 4 条：host 本地 session log + gateway 审计双写（本文件是 gateway 侧）。
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
		console.log(`[hive-audit] ${line}`);
	}
};
//#endregion
export { AuditLog };

//# sourceMappingURL=audit.js.map