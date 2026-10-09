// Index records (CCHS.spec.md §4.3) for hosts without localStorage. A signer
// that runs for real must persist them: the record of which leaves were
// signed is what keeps a leaf from ever being signed twice.

import { MemoryRecordStore, recordStore, removeRecord, setRecordStore, type RecordStore } from "../../wallet/src/aegis/recordStore";

export { MemoryRecordStore, recordStore, removeRecord, setRecordStore };
export type { RecordStore };

/**
 * A JSON file, rewritten on every change (records are a few hundred bytes).
 * Node only; pass the `fs` module in so the SDK stays free of node imports:
 *
 *   import fs from 'node:fs';
 *   setRecordStore(new JsonFileRecordStore('./aegis-records.json', fs));
 */
export class JsonFileRecordStore implements RecordStore {
  private m: Record<string, string>;
  constructor(private path: string, private fs: { readFileSync(p: string, e: "utf8"): string; writeFileSync(p: string, d: string): void; existsSync(p: string): boolean }) {
    this.m = fs.existsSync(path) ? (JSON.parse(fs.readFileSync(path, "utf8")) as Record<string, string>) : {};
  }
  getItem(k: string) { return this.m[k] ?? null; }
  setItem(k: string, v: string) { this.m[k] = v; this.flush(); }
  removeItem(k: string) { delete this.m[k]; this.flush(); }
  private flush() { this.fs.writeFileSync(this.path, JSON.stringify(this.m, null, 2)); }
}
