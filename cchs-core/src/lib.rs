//! CCHS-S-20 verifier core — Chain-Cached Hypertree Signatures.
//!
//! Parameter set: SHA-256, WOTS+ with w = 16 and 67 chains (64 message digits
//! + 3 checksum digits), two tree layers of height 10 (2^20 signatures), and a
//! single-layer recovery tree of height 8.
//!
//! This crate is `no_std`, allocation-free and dependency-free. The host chain
//! injects its SHA-256 through the [`Sha256`] trait so that the verifier can
//! use a syscall (Solana), a host function (NEAR) or a pure-Rust hash
//! (CosmWasm, native tests). Everything here is byte-exact with
//! `evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`; the shared ground
//! truth is `evm/test/fixtures/cchs-s-20.json`.
//!
//! The [`compact`] module implements the second parameter set, CCHS-C-20
//! (n = 24, w = 256, 26 chains, same tree shape), whose 864-byte layer fits a
//! single Solana packet. Its ground truth is `evm/test/fixtures/cchs-c-20.json`.
//!
//! Spec: `../CCHS.spec.md`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub mod compact;

// ------------------------------------------------------------------ params

/// Winternitz parameter.
pub const W: usize = 16;
/// Message chains (256 bits / 4 bits per digit).
pub const LEN_MSG: usize = 64;
/// Checksum chains (max checksum 64 × 15 = 960 < 16^3).
pub const LEN_CSUM: usize = 3;
/// Total WOTS+ chains.
pub const LEN: usize = LEN_MSG + LEN_CSUM;
/// Tree height per hypertree layer.
pub const H: usize = 10;
/// Leaves per tree.
pub const LEAVES: u64 = 1 << H;
/// Total signature capacity (two layers).
pub const CAPACITY: u64 = 1 << (2 * H);
/// Recovery tree height.
pub const REC_H: usize = 8;
/// Recovery signatures available.
pub const REC_CAPACITY: u64 = 1 << REC_H;

/// ADRS layer id of the bottom (signing) layer.
pub const LAYER_BOTTOM: u8 = 0x00;
/// ADRS layer id of the top layer.
pub const LAYER_TOP: u8 = 0x01;
/// ADRS layer id of the recovery tree.
pub const LAYER_RECOVERY: u8 = 0xFF;

/// ADRS type: WOTS+ chain step.
pub const TYPE_CHAIN: u8 = 0x00;
/// ADRS type: WOTS+ public-key compression (leaf).
pub const TYPE_LEAF: u8 = 0x01;
/// ADRS type: Merkle internal node.
pub const TYPE_NODE: u8 = 0x02;

// ------------------------------------------------------------------- hash

/// Incremental SHA-256 supplied by the host.
///
/// `finish` returns the digest of everything fed since the last `finish`
/// (or construction) and resets the state so the value can be reused.
/// `Default` must produce an empty state.
pub trait Sha256: Default {
    fn update(&mut self, data: &[u8]);
    fn finish(&mut self) -> [u8; 32];
}

#[cfg(feature = "sha2")]
impl Sha256 for sha2::Sha256 {
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(self, data);
    }
    fn finish(&mut self) -> [u8; 32] {
        sha2::Digest::finalize_reset(self).into()
    }
}

// ------------------------------------------------------------------- ADRS

/// Bytes of the per-tree public seed carried in every ADRS.
pub const SEED_BYTES: usize = 16;
/// The public seed of a key tree: part of the public key, stored with the
/// roots, and the last 16 bytes of every ADRS.
pub type Seed = [u8; SEED_BYTES];

/// `ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16)`
///
/// The seed makes every hash call of one tree a different function from the
/// same position in any other tree (another account, chain or epoch), which
/// the multi-target security argument needs (spec §2.2, §5.5).
pub fn adrs(seed: &Seed, layer: u8, tree_idx: u64, typ: u8, leaf_idx: u32, chain_idx: u8, step: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = layer;
    a[1..9].copy_from_slice(&tree_idx.to_be_bytes());
    a[9] = typ;
    a[10..14].copy_from_slice(&leaf_idx.to_be_bytes());
    a[14] = chain_idx;
    a[15] = step;
    a[16..].copy_from_slice(seed);
    a
}

// ----------------------------------------------------------------- digits

/// 64 base-16 message digits (high nibble first) followed by 3 base-16
/// checksum digits of `csum = Σ (15 - d_i)`, big-endian.
pub fn digits(msg: &[u8; 32]) -> [u8; LEN] {
    let mut d = [0u8; LEN];
    let mut csum: u32 = 0;
    for i in 0..32 {
        let hi = msg[i] >> 4;
        let lo = msg[i] & 0x0f;
        d[2 * i] = hi;
        d[2 * i + 1] = lo;
        csum += (15 - hi as u32) + (15 - lo as u32);
    }
    d[64] = ((csum >> 8) & 0x0f) as u8;
    d[65] = ((csum >> 4) & 0x0f) as u8;
    d[66] = (csum & 0x0f) as u8;
    d
}

// ------------------------------------------------------------------ WOTS+

/// From a WOTS+ signature on `msg`, complete every chain to its end and
/// compress the 67 chain ends into the leaf hash
/// `H(ADRS(layer, tree, 0x01, leaf, 0, 0) ‖ pk_0 ‖ … ‖ pk_66)`.
///
/// `h` is used for the chain steps; a second hasher (`S::default()`)
/// accumulates the leaf so no 2176-byte buffer is needed.
pub fn wots_leaf<S: Sha256>(
    h: &mut S,
    seed: &Seed,
    layer: u8,
    tree_idx: u64,
    leaf_idx: u32,
    msg: &[u8; 32],
    wots: &[[u8; 32]; LEN],
) -> [u8; 32] {
    let d = digits(msg);
    let mut leaf = S::default();
    leaf.update(&adrs(seed, layer, tree_idx, TYPE_LEAF, leaf_idx, 0, 0));

    let mut a = adrs(seed, layer, tree_idx, TYPE_CHAIN, leaf_idx, 0, 0);
    let last_step = (W - 1) as u8;
    for c in 0..LEN {
        let mut x = wots[c];
        a[14] = c as u8;
        let mut s = d[c];
        while s < last_step {
            a[15] = s;
            h.update(&a);
            h.update(&x);
            x = h.finish();
            s += 1;
        }
        leaf.update(&x);
    }
    leaf.finish()
}

// ----------------------------------------------------------------- Merkle

/// `T_node(adrs, l, r)`; child order chosen by the parity of the current
/// position (`odd == true` means the current node is the right child).
pub fn node<S: Sha256>(h: &mut S, a: &[u8; 32], cur: &[u8; 32], sib: &[u8; 32], odd: bool) -> [u8; 32] {
    h.update(a);
    if odd {
        h.update(sib);
        h.update(cur);
    } else {
        h.update(cur);
        h.update(sib);
    }
    h.finish()
}

/// Walk the authentication path from `leaf` at `leaf_idx` to the root.
/// At level `k` the node ADRS uses `leafIdx = pos >> 1` and `chainIdx = k`.
pub fn root_from_path<S: Sha256>(
    h: &mut S,
    seed: &Seed,
    layer: u8,
    tree_idx: u64,
    leaf: [u8; 32],
    leaf_idx: u32,
    auth: &[[u8; 32]],
) -> [u8; 32] {
    let mut r = leaf;
    let mut pos = leaf_idx;
    for (k, sib) in auth.iter().enumerate() {
        let a = adrs(seed, layer, tree_idx, TYPE_NODE, pos >> 1, k as u8, 0);
        r = node(h, &a, &r, sib, (pos & 1) == 1);
        pos >>= 1;
    }
    r
}

/// Recompute the root of tree `(layer, tree_idx)` from a WOTS+ signature on
/// `msg` at `leaf_idx` and its authentication path.
///
/// Exactly `height` siblings of `auth` are consumed; the caller must ensure
/// `auth.len() >= height` (the state-machine wrappers below check this and
/// return [`CchsError::BadLength`] instead of panicking).
pub fn verify_layer<S: Sha256>(
    h: &mut S,
    seed: &Seed,
    layer: u8,
    tree_idx: u64,
    leaf_idx: u32,
    msg: &[u8; 32],
    wots: &[[u8; 32]; LEN],
    auth: &[[u8; 32]],
    height: usize,
) -> [u8; 32] {
    let leaf = wots_leaf(h, seed, layer, tree_idx, leaf_idx, msg, wots);
    root_from_path(h, seed, layer, tree_idx, leaf, leaf_idx, &auth[..height])
}

// ------------------------------------------------------------------ state

/// Verification failure reasons. Mirrors the Solidity custom errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CchsError {
    /// All 2^20 leaves (or all 256 recovery leaves) have been used, or the
    /// requested leaf index is `>= 2^20`.
    Exhausted,
    /// Requested leaf index is below `next_idx`: already consumed or abandoned.
    IndexUsed,
    /// Subtree not cached yet and no top-layer proof was supplied.
    MissingTopLayer,
    /// Bottom root differs from the cached subtree root.
    BadSubtreeRoot,
    /// Top-layer path does not reach `root`.
    BadTopRoot,
    /// Recovery path does not reach `rec_root`.
    BadRecovery,
    /// A root of all zero bytes is not accepted.
    ZeroRoot,
    /// Authentication path shorter than the tree height.
    BadLength,
}

impl CchsError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CchsError::Exhausted => "exhausted",
            CchsError::IndexUsed => "index used",
            CchsError::MissingTopLayer => "missing top layer",
            CchsError::BadSubtreeRoot => "bad subtree root",
            CchsError::BadTopRoot => "bad top root",
            CchsError::BadRecovery => "bad recovery",
            CchsError::ZeroRoot => "zero root",
            CchsError::BadLength => "bad length",
        }
    }
}

impl core::fmt::Display for CchsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CchsError {}

/// One layer of a signature: 67 chain values and an authentication path.
#[derive(Clone, Copy)]
pub struct LayerSig<'a> {
    pub wots: &'a [[u8; 32]; LEN],
    pub auth: &'a [[u8; 32]],
}

/// Result of a successful [`CchsState::execute_verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecuteOutcome {
    /// Leaf index that was consumed.
    pub idx: u64,
    /// Bottom tree index `idx >> H`.
    pub tree_idx: u64,
    /// Leaf within the bottom tree `idx & (LEAVES - 1)`.
    pub leaf_idx: u32,
    /// Verified bottom subtree root `R_0`.
    pub subtree_root: [u8; 32],
    /// `true` when the top layer was verified now and the host must store
    /// `subtree_root` under `(epoch, tree_idx)`.
    pub cache_write: bool,
}

/// Account state shared by every chain adapter. The subtree cache itself is
/// host storage; the host looks up `(epoch, tree_idx)` and passes the result
/// in, then performs the write requested by [`ExecuteOutcome::cache_write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CchsState {
    pub root: [u8; 32],
    pub rec_root: [u8; 32],
    /// Public seed of the current key tree (every ADRS carries it).
    pub seed: Seed,
    pub epoch: u64,
    /// Lowest leaf index still available: every leaf below it is consumed
    /// or abandoned. The signer picks any `idx >= next_idx`.
    pub next_idx: u64,
    pub nonce: u64,
    pub rec_nonce: u64,
}

impl CchsState {
    /// Fresh account. Rejects all-zero roots.
    pub fn new(root: [u8; 32], rec_root: [u8; 32], seed: Seed) -> Result<Self, CchsError> {
        if root == [0u8; 32] || rec_root == [0u8; 32] {
            return Err(CchsError::ZeroRoot);
        }
        Ok(CchsState { root, rec_root, seed, epoch: 0, next_idx: 0, nonce: 0, rec_nonce: 0 })
    }

    /// Bottom tree index of the lowest still-available leaf (`next_idx`).
    pub fn tree_idx(&self) -> u64 {
        self.next_idx >> H
    }

    /// Leaf index within the bottom tree of the lowest still-available leaf.
    pub fn leaf_idx(&self) -> u32 {
        (self.next_idx & (LEAVES - 1)) as u32
    }

    /// Whether an `execute` must carry the top layer, given the host's
    /// lookup of `cached[(epoch, idx >> H)]` for the leaf it targets.
    pub fn needs_top_layer(cached: Option<[u8; 32]>) -> bool {
        normalize_cached(cached).is_none()
    }

    /// Index discipline: `idx` must be `>= next_idx` ([`CchsError::IndexUsed`])
    /// and `< 2^20` ([`CchsError::Exhausted`]).
    pub fn check_idx(&self, idx: u64) -> Result<(), CchsError> {
        if idx < self.next_idx {
            return Err(CchsError::IndexUsed);
        }
        if idx >= CAPACITY {
            return Err(CchsError::Exhausted);
        }
        Ok(())
    }

    /// Verify a signature on the 32-byte `msg` for the signer-chosen leaf
    /// `idx`.
    ///
    /// * `idx` — must satisfy `next_idx <= idx < 2^20`. Leaves below `idx`
    ///   are abandoned forever: on success `next_idx` becomes `idx + 1`.
    ///   The host binds `idx` into `msg`, so only the signer can skip.
    /// * `cached` — host lookup of `cachedRoot[(epoch, idx >> H)]`
    ///   (`None` or all-zero means "not cached"). When the cache is empty
    ///   `l1` is required and verified against `root`; when it is filled a
    ///   supplied `l1` is ignored and only the bottom root is compared.
    /// * On success `next_idx = idx + 1`, `nonce += 1`, and the outcome
    ///   tells the host whether to write the cache. On error the state is
    ///   left untouched.
    pub fn execute_verify<S: Sha256>(
        &mut self,
        h: &mut S,
        idx: u64,
        msg: &[u8; 32],
        l0: LayerSig<'_>,
        l1: Option<LayerSig<'_>>,
        cached: Option<[u8; 32]>,
    ) -> Result<ExecuteOutcome, CchsError> {
        self.check_idx(idx)?;
        if l0.auth.len() < H {
            return Err(CchsError::BadLength);
        }
        let tree_idx = idx >> H;
        let leaf_idx = (idx & (LEAVES - 1)) as u32;

        let r0 = verify_layer(h, &self.seed, LAYER_BOTTOM, tree_idx, leaf_idx, msg, l0.wots, l0.auth, H);

        let cache_write = match normalize_cached(cached) {
            Some(c) => {
                // Subtree already registered: a redundant top layer is ignored.
                if c != r0 {
                    return Err(CchsError::BadSubtreeRoot);
                }
                false
            }
            None => {
                let l1 = l1.ok_or(CchsError::MissingTopLayer)?;
                if l1.auth.len() < H {
                    return Err(CchsError::BadLength);
                }
                // Top layer: tree 0, leaf = bottom tree index, message = R_0.
                let r1 = verify_layer(h, &self.seed, LAYER_TOP, 0, tree_idx as u32, &r0, l1.wots, l1.auth, H);
                if r1 != self.root {
                    return Err(CchsError::BadTopRoot);
                }
                true
            }
        };

        self.next_idx = idx + 1;
        self.nonce = self.nonce.wrapping_add(1);
        Ok(ExecuteOutcome { idx, tree_idx, leaf_idx, subtree_root: r0, cache_write })
    }

    /// Verify a recovery signature on `msg` under `rec_root` at leaf
    /// `rec_nonce` (layer `0xFF`, tree 0, height 8, hashed with the current
    /// seed). On success installs the new public key (roots and seed), resets
    /// `next_idx`, bumps `epoch` (which logically clears the subtree cache)
    /// and `rec_nonce`. Returns the new epoch. The host must bind `new_seed`
    /// into `msg` together with the new roots.
    pub fn recover_verify<S: Sha256>(
        &mut self,
        h: &mut S,
        msg: &[u8; 32],
        new_root: [u8; 32],
        new_rec_root: [u8; 32],
        new_seed: Seed,
        wots: &[[u8; 32]; LEN],
        auth: &[[u8; 32]],
    ) -> Result<u64, CchsError> {
        if new_root == [0u8; 32] || new_rec_root == [0u8; 32] {
            return Err(CchsError::ZeroRoot);
        }
        let rn = self.rec_nonce;
        if rn >= REC_CAPACITY {
            return Err(CchsError::Exhausted);
        }
        if auth.len() < REC_H {
            return Err(CchsError::BadLength);
        }
        let r = verify_layer(h, &self.seed, LAYER_RECOVERY, 0, rn as u32, msg, wots, auth, REC_H);
        if r != self.rec_root {
            return Err(CchsError::BadRecovery);
        }
        self.root = new_root;
        self.rec_root = new_rec_root;
        self.seed = new_seed;
        self.next_idx = 0;
        self.epoch = self.epoch.wrapping_add(1);
        self.rec_nonce = rn + 1;
        Ok(self.epoch)
    }
}

fn normalize_cached(cached: Option<[u8; 32]>) -> Option<[u8; 32]> {
    match cached {
        Some(c) if c != [0u8; 32] => Some(c),
        _ => None,
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adrs_layout() {
        let seed: Seed = core::array::from_fn(|i| 0xA0 + i as u8);
        let a = adrs(&seed, 0x01, 0x0102030405060708, 0x02, 0x0A0B0C0D, 0x21, 0x0E);
        assert_eq!(a[0], 0x01);
        assert_eq!(&a[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(a[9], 0x02);
        assert_eq!(&a[10..14], &[0x0A, 0x0B, 0x0C, 0x0D]);
        assert_eq!(a[14], 0x21);
        assert_eq!(a[15], 0x0E);
        assert_eq!(&a[16..], &seed);
    }

    #[test]
    fn digits_checksum() {
        // All-zero message: every digit 0, csum = 64 * 15 = 960 = 0x3C0.
        let d = digits(&[0u8; 32]);
        assert!(d[..64].iter().all(|&x| x == 0));
        assert_eq!(&d[64..], &[0x3, 0xC, 0x0]);
        // All-0xFF message: every digit 15, csum = 0.
        let d = digits(&[0xFFu8; 32]);
        assert!(d[..64].iter().all(|&x| x == 15));
        assert_eq!(&d[64..], &[0, 0, 0]);
        // Nibble order: high nibble first.
        let mut m = [0u8; 32];
        m[0] = 0xA5;
        let d = digits(&m);
        assert_eq!(d[0], 0xA);
        assert_eq!(d[1], 0x5);
    }

    #[test]
    fn state_rejects_zero_roots() {
        assert_eq!(CchsState::new([0u8; 32], [1u8; 32], [0u8; 16]), Err(CchsError::ZeroRoot));
        assert_eq!(CchsState::new([1u8; 32], [0u8; 32], [0u8; 16]), Err(CchsError::ZeroRoot));
        assert!(CchsState::new([1u8; 32], [2u8; 32], [0u8; 16]).is_ok());
    }
}
