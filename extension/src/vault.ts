// The mnemonic at rest: AES-256-GCM under a key stretched from the user's
// password with PBKDF2-SHA-256 (600 000 iterations, 16-byte salt), stored in
// chrome.storage.local. In memory only while the panel is unlocked. The
// password is never stored; forgetting it means re-entering the mnemonic,
// which is the only real secret.

const ITERATIONS = 600_000;
const KEY = "aegis/vault/v1";

type Stored = { v: 1; salt: string; iv: string; ct: string };

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password.normalize("NFKD")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: ITERATIONS },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );
}

const storage = {
  async get(): Promise<Stored | null> {
    if (typeof chrome !== "undefined" && chrome.storage?.local) {
      const r = await chrome.storage.local.get(KEY);
      return (r[KEY] as Stored | undefined) ?? null;
    }
    const s = localStorage.getItem(KEY); // dev server fallback
    return s ? (JSON.parse(s) as Stored) : null;
  },
  async set(v: Stored | null): Promise<void> {
    if (typeof chrome !== "undefined" && chrome.storage?.local) {
      if (v) await chrome.storage.local.set({ [KEY]: v }); else await chrome.storage.local.remove(KEY);
      return;
    }
    if (v) localStorage.setItem(KEY, JSON.stringify(v)); else localStorage.removeItem(KEY);
  },
};

export async function hasVault(): Promise<boolean> {
  return (await storage.get()) !== null;
}

export async function createVault(mnemonic: string, password: string): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, new TextEncoder().encode(mnemonic.trim())));
  await storage.set({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
}

/** Returns the mnemonic, or null when the password is wrong. */
export async function unlockVault(password: string): Promise<string | null> {
  const s = await storage.get();
  if (!s) return null;
  try {
    const key = await deriveKey(password, unb64(s.salt));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv) as BufferSource }, key, unb64(s.ct) as BufferSource);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

export async function destroyVault(): Promise<void> {
  await storage.set(null);
}
