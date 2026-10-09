// Where the client keeps its write-ahead index records (CCHS.spec.md §4.3):
// the highest leaf signed per (chain, account, epoch, lane), the recovery
// leaves used, the lookup-table addresses. Nothing secret is ever stored.
//
// Browsers use localStorage; other hosts (the SDK in node, tests) install a
// store of their own with `setRecordStore`. Without either, records live in
// memory for the process, which is enough for a single run but not across
// restarts: a host that signs for real must persist them.

export interface RecordStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  /** Optional; stores without it get the key set to the empty string instead. */
  removeItem?(key: string): void;
}

export class MemoryRecordStore implements RecordStore {
  private m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

/** Delete a record on any store. */
export function removeRecord(s: RecordStore, key: string): void {
  if (s.removeItem) s.removeItem(key); else s.setItem(key, '');
}

let store: RecordStore | null = null;

/** Replace the record store (SDK hosts). Returns the previous one. */
export function setRecordStore(s: RecordStore): RecordStore | null {
  const prev = store;
  store = s;
  return prev;
}

/** The active store: the one installed, else `localStorage` when the host has it, else process memory. */
export function recordStore(): RecordStore {
  if (store) return store;
  const ls = (globalThis as { localStorage?: RecordStore }).localStorage;
  if (ls && typeof ls.getItem === 'function') return ls;
  store = new MemoryRecordStore();
  return store;
}
