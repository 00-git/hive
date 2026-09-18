//#region src/audit.d.ts
interface AuditEntry {
  ts: number;
  traceId?: string;
  actor: string;
  action: string;
  target: string;
  decision: 'allow' | 'deny' | 'info';
  detail?: unknown;
}
declare class AuditLog {
  #private;
  constructor(file?: string);
  write(entry: AuditEntry): void;
}
//#endregion
export { AuditEntry, AuditLog };
//# sourceMappingURL=audit.d.ts.map