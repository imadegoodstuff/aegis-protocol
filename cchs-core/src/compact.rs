//! CCHS-C-20 verifier — the single-packet parameter set.
//!
//! Same hypertree shape as CCHS-S-20 (two layers of height 10, recovery tree
//! of height 8, identical 32-byte ADRS) but with
//!
//! * `n = 24`: every hash output is SHA-256 truncated to its first 24 bytes
//!   (192-bit preimage security),
//! * `w = 256`: one WOTS+ chain per message byte plus two checksum chains,
//!   `LEN = 26`.
//!
//! One layer is `26 × 24 + 10 × 24 = 864` bytes, so the cached (hot) path of
//! a signature fits one 1 232-byte Solana packet. The top layer is verified
//! in its own transaction; [`verify_top_layer`] and [`bottom_root`] expose
//! the two halves so a host can split cache filling from execution, while
//! [`CchsState::execute_verify`] keeps the one-shot state machine of the
//! S-20 API for hosts that do not need the split.
//!
//! Byte-exact with `wallet/src/aegis/cchsCompact.ts`; the shared ground
//! truth is `evm/test/fixtures/cchs-c-20.json`.

use crate::{
    adrs, CchsError, Sha256, LAYER_BOTTOM, LAYER_RECOVERY, LAYER_TOP, TYPE_CHAIN, TYPE_LEAF,
    TYPE_NODE,
};

// ------------------------------------------------------------------ params

/// Hash output bytes (SHA-256 truncated).
pub const N: usize = 24;
/// Winternitz parameter: one chain per message byte.
pub const W: usize = 256;
/// Message chains (24 message bytes).
pub const LEN_MSG: usize = 24;
/// Checksum chains (max checksum 24 × 255 = 6120 < 256^2).
pub const LEN_CSUM: usize = 2;
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
/// Bytes of one layer: 26 chain values + 10 siblings.
pub const LAYER_BYTES: usize = (LEN + H) * N;
/// Bytes of a recovery signature: 26 chain values + 8 siblings.
pub const RECOVERY_BYTES: usize = (LEN + REC_H) * N;

/// A 24-byte hash value (root, node, chain value or message).
pub type Hash = [u8; N];

/// All-zero hash; used as the "absent" marker in caches.
pub const ZERO: Hash = [0u8; N];

// ------------------------------------------------------------------- hash

/// SHA-256 truncated to 24 bytes.
#[inline]
fn trunc(d: [u8; 32]) -> Hash {
    let mut out = [0u8; N];
    out.copy_from_slice(&d[..N]);
    out
}

/// Finish the hasher and truncate.
#[inline]
fn finish_n<S: Sha256>(h: &mut S) -> Hash {
    trunc(h.finish())
}

// ----------------------------------------------------------------- digits

/// The 24 message bytes themselves followed by the 2-byte big-endian
/// checksum `csum = Σ (255 - m_i)`.
pub fn digits(msg: &Hash) -> [u8; LEN] {
    let mut d = [0u8; LEN];
    let mut csum: u32 = 0;
    for i in 0..LEN_MSG {
        d[i] = msg[i];
        csum += 255 - msg[i] as u32;
    }
    d[LEN_MSG] = ((csum >> 8) & 0xff) as u8;
    d[LEN_MSG + 1] = (csum & 0xff) as u8;
    d
}

// ------------------------------------------------------------------ WOTS+

/// From a WOTS+ signature on `msg`, complete every chain to its end and
/// compress the 26 chain ends into the leaf hash
/// `H(ADRS(layer, tree, 0x01, leaf, 0, 0) ‖ pk_0 ‖ … ‖ pk_25)[0..24)`.
///
/// `h` is used for the chain steps (`H(ADRS ‖ x)[0..24)`, 56-byte input);
/// a second hasher accumulates the 656-byte leaf input.
pub fn wots_leaf<S: Sha256>(
    h: &mut S,
    layer: u8,
    tree_idx: u64,
    leaf_idx: u32,
    msg: &Hash,
    wots: &[Hash; LEN],
) -> Hash {
    let d = digits(msg);
    let mut leaf = S::default();
    leaf.update(&adrs(layer, tree_idx, TYPE_LEAF, leaf_idx, 0, 0));

    let mut a = adrs(layer, tree_idx, TYPE_CHAIN, leaf_idx, 0, 0);
    let last_step = (W - 1) as u8; // 255
    for c in 0..LEN {
        let mut x = wots[c];
        a[14] = c as u8;
        let mut s = d[c];
        // `s` never exceeds 255, so the increment cannot overflow.
        while s < last_step {
            a[15] = s;
            h.update(&a);
            h.update(&x);
            x = finish_n(h);
            s += 1;
        }
        leaf.update(&x);
    }
    finish_n(&mut leaf)
}

// ----------------------------------------------------------------- Merkle

/// `T_node(adrs, l, r)[0..24)`; child order chosen by the parity of the
/// current position (`odd == true` means the current node is the right child).
pub fn node<S: Sha256>(h: &mut S, a: &[u8; 32], cur: &Hash, sib: &Hash, odd: bool) -> Hash {
    h.update(a);
    if odd {
        h.update(sib);
        h.update(cur);
    } else {
        h.update(cur);
        h.update(sib);
    }
    finish_n(h)
}

/// Walk the authentication path from `leaf` at `leaf_idx` to the root.
/// At level `k` the node ADRS uses `leafIdx = pos >> 1` and `chainIdx = k`.
pub fn root_from_path<S: Sha256>(
    h: &mut S,
    layer: u8,
    tree_idx: u64,
    leaf: Hash,
    leaf_idx: u32,
    auth: &[Hash],
) -> Hash {
    let mut r = leaf;
    let mut pos = leaf_idx;
    for (k, sib) in auth.iter().enumerate() {
        let a = adrs(layer, tree_idx, TYPE_NODE, pos >> 1, k as u8, 0);
        r = node(h, &a, &r, sib, (pos & 1) == 1);
        pos >>= 1;
    }
    r
}

/// Recompute the root of tree `(layer, tree_idx)` from a WOTS+ signature on
/// `msg` at `leaf_idx` and its authentication path.
///
/// Exactly `height` siblings of `auth` are consumed; the caller must ensure
/// `auth.len() >= height` (the wrappers below check this and return
/// [`CchsError::BadLength`] instead of panicking).
pub fn verify_layer<S: Sha256>(
    h: &mut S,
    layer: u8,
    tree_idx: u64,
    leaf_idx: u32,
    msg: &Hash,
    wots: &[Hash; LEN],
    auth: &[Hash],
    height: usize,
) -> Hash {
    let leaf = wots_leaf(h, layer, tree_idx, leaf_idx, msg, wots);
    root_from_path(h, layer, tree_idx, leaf, leaf_idx, &auth[..height])
}

// ------------------------------------------------------------- signature

/// One layer of a signature: 26 chain values and an authentication path.
#[derive(Clone, Copy)]
pub struct LayerSig<'a> {
    pub wots: &'a [Hash; LEN],
    pub auth: &'a [Hash],
}

/// Bottom tree index of leaf `idx`.
#[inline]
pub fn tree_idx_of(idx: u64) -> u64 {
    idx >> H
}

/// Leaf position of leaf `idx` within its bottom tree.
#[inline]
pub fn leaf_idx_of(idx: u64) -> u32 {
    (idx & (LEAVES - 1)) as u32
}

/// Bottom subtree root `R_0` recomputed from a layer-0 signature on `msg`
/// at leaf `idx` — the value a verifier compares with its cache.
///
/// Errors: [`CchsError::Exhausted`] if `idx >= 2^20`,
/// [`CchsError::BadLength`] if fewer than 10 siblings are supplied.
pub fn bottom_root<S: Sha256>(
    h: &mut S,
    idx: u64,
    msg: &Hash,
    l0: LayerSig<'_>,
) -> Result<Hash, CchsError> {
    if idx >= CAPACITY {
        return Err(CchsError::Exhausted);
    }
    if l0.auth.len() < H {
        return Err(CchsError::BadLength);
    }
    Ok(verify_layer(
        h,
        LAYER_BOTTOM,
        tree_idx_of(idx),
        leaf_idx_of(idx),
        msg,
        l0.wots,
        l0.auth,
        H,
    ))
}

/// Verify the top-layer proof that bottom tree `tree_idx` has root `r0`:
/// top tree 0, leaf `tree_idx`, message `r0`, must reach `root`.
///
/// Errors: [`CchsError::Exhausted`] if `tree_idx >= 2^10`,
/// [`CchsError::BadLength`] if fewer than 10 siblings are supplied,
/// [`CchsError::BadTopRoot`] if the path does not end at `root`.
pub fn verify_top_layer<S: Sha256>(
    h: &mut S,
    root: &Hash,
    tree_idx: u64,
    r0: &Hash,
    l1: LayerSig<'_>,
) -> Result<(), CchsError> {
    if tree_idx >= LEAVES {
        return Err(CchsError::Exhausted);
    }
    if l1.auth.len() < H {
        return Err(CchsError::BadLength);
    }
    let r1 = verify_layer(h, LAYER_TOP, 0, tree_idx as u32, r0, l1.wots, l1.auth, H);
    if r1 != *root {
        return Err(CchsError::BadTopRoot);
    }
    Ok(())
}

// ------------------------------------------------------------------ state

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
    pub subtree_root: Hash,
    /// `true` when the top layer was verified now and the host must store
    /// `subtree_root` under `(epoch, tree_idx)`.
    pub cache_write: bool,
}

/// Account state shared by every chain adapter. The subtree cache itself is
/// host storage; the host looks up `(epoch, tree_idx)` and passes the result
/// in, then performs the write requested by [`ExecuteOutcome::cache_write`]
/// (or fills the cache separately through [`verify_top_layer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CchsState {
    pub root: Hash,
    pub rec_root: Hash,
    pub epoch: u64,
    pub next_idx: u64,
    pub nonce: u64,
    pub rec_nonce: u64,
}

impl CchsState {
    /// Fresh account. Rejects all-zero roots.
    pub fn new(root: Hash, rec_root: Hash) -> Result<Self, CchsError> {
        if root == ZERO || rec_root == ZERO {
            return Err(CchsError::ZeroRoot);
        }
        Ok(CchsState { root, rec_root, epoch: 0, next_idx: 0, nonce: 0, rec_nonce: 0 })
    }

    /// Bottom tree index of the next signature.
    pub fn tree_idx(&self) -> u64 {
        tree_idx_of(self.next_idx)
    }

    /// Leaf index within the bottom tree of the next signature.
    pub fn leaf_idx(&self) -> u32 {
        leaf_idx_of(self.next_idx)
    }

    /// Whether the next `execute` must carry the top layer, given the host's
    /// lookup of `cached[(epoch, tree_idx)]`.
    pub fn needs_top_layer(cached: Option<Hash>) -> bool {
        normalize_cached(cached).is_none()
    }

    /// Verify a signature on the 24-byte `msg` for leaf `next_idx`.
    ///
    /// * `cached` — host lookup of `cachedRoot[(epoch, next_idx >> H)]`
    ///   (`None` or all-zero means "not cached").
    /// * On success `next_idx` and `nonce` are incremented and the outcome
    ///   tells the host whether to write the cache. On error the state is
    ///   left untouched.
    pub fn execute_verify<S: Sha256>(
        &mut self,
        h: &mut S,
        msg: &Hash,
        l0: LayerSig<'_>,
        l1: Option<LayerSig<'_>>,
        cached: Option<Hash>,
    ) -> Result<ExecuteOutcome, CchsError> {
        let idx = self.next_idx;
        let r0 = bottom_root(h, idx, msg, l0)?;
        let tree_idx = tree_idx_of(idx);
        let leaf_idx = leaf_idx_of(idx);

        let cache_write = match normalize_cached(cached) {
            Some(c) => {
                if c != r0 {
                    return Err(CchsError::BadSubtreeRoot);
                }
                false
            }
            None => {
                let l1 = l1.ok_or(CchsError::MissingTopLayer)?;
                verify_top_layer(h, &self.root, tree_idx, &r0, l1)?;
                true
            }
        };

        self.next_idx = idx + 1;
        self.nonce = self.nonce.wrapping_add(1);
        Ok(ExecuteOutcome { idx, tree_idx, leaf_idx, subtree_root: r0, cache_write })
    }

    /// Verify a signature for leaf `next_idx` whose bottom root is already
    /// cached (`cached` is the host's non-zero cache entry). This is the
    /// one-packet path: no top layer is accepted or needed. On success
    /// `next_idx` and `nonce` are incremented.
    pub fn execute_cached<S: Sha256>(
        &mut self,
        h: &mut S,
        msg: &Hash,
        l0: LayerSig<'_>,
        cached: Hash,
    ) -> Result<ExecuteOutcome, CchsError> {
        if cached == ZERO {
            return Err(CchsError::MissingTopLayer);
        }
        self.execute_verify(h, msg, l0, None, Some(cached))
    }

    /// Verify a recovery signature on `msg` under `rec_root` at leaf
    /// `rec_nonce` (layer `0xFF`, tree 0, height 8). On success installs the
    /// new roots, resets `next_idx`, bumps `epoch` (which logically clears
    /// the subtree cache) and `rec_nonce`. Returns the new epoch.
    pub fn recover_verify<S: Sha256>(
        &mut self,
        h: &mut S,
        msg: &Hash,
        new_root: Hash,
        new_rec_root: Hash,
        wots: &[Hash; LEN],
        auth: &[Hash],
    ) -> Result<u64, CchsError> {
        if new_root == ZERO || new_rec_root == ZERO {
            return Err(CchsError::ZeroRoot);
        }
        let rn = self.rec_nonce;
        if rn >= REC_CAPACITY {
            return Err(CchsError::Exhausted);
        }
        if auth.len() < REC_H {
            return Err(CchsError::BadLength);
        }
        let r = verify_layer(h, LAYER_RECOVERY, 0, rn as u32, msg, wots, auth, REC_H);
        if r != self.rec_root {
            return Err(CchsError::BadRecovery);
        }
        self.root = new_root;
        self.rec_root = new_rec_root;
        self.next_idx = 0;
        self.epoch = self.epoch.wrapping_add(1);
        self.rec_nonce = rn + 1;
        Ok(self.epoch)
    }
}

fn normalize_cached(cached: Option<Hash>) -> Option<Hash> {
    match cached {
        Some(c) if c != ZERO => Some(c),
        _ => None,
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(LEN, 26);
        assert_eq!(LAYER_BYTES, 864);
        assert_eq!(RECOVERY_BYTES, 816);
        assert_eq!(32 + LEN * N, 656);
    }

    #[test]
    fn digits_checksum() {
        // All-zero message: csum = 24 * 255 = 6120 = 0x17E8.
        let d = digits(&[0u8; N]);
        assert!(d[..LEN_MSG].iter().all(|&x| x == 0));
        assert_eq!(&d[LEN_MSG..], &[0x17, 0xE8]);
        // All-0xFF message: csum = 0.
        let d = digits(&[0xFFu8; N]);
        assert!(d[..LEN_MSG].iter().all(|&x| x == 0xFF));
        assert_eq!(&d[LEN_MSG..], &[0, 0]);
        // Message bytes are the digits.
        let mut m = [0u8; N];
        m[0] = 0xA5;
        m[23] = 0x01;
        let d = digits(&m);
        assert_eq!(d[0], 0xA5);
        assert_eq!(d[23], 0x01);
        // csum = 6120 - 0xA5 - 1 = 5954 = 0x1742.
        assert_eq!(&d[LEN_MSG..], &[0x17, 0x42]);
    }

    #[test]
    fn index_split() {
        assert_eq!(tree_idx_of(0), 0);
        assert_eq!(leaf_idx_of(0), 0);
        assert_eq!(tree_idx_of(1023), 0);
        assert_eq!(leaf_idx_of(1023), 1023);
        assert_eq!(tree_idx_of(1024), 1);
        assert_eq!(leaf_idx_of(1024), 0);
        assert_eq!(tree_idx_of(CAPACITY - 1), LEAVES - 1);
        assert_eq!(leaf_idx_of(CAPACITY - 1), (LEAVES - 1) as u32);
    }

    #[test]
    fn state_rejects_zero_roots() {
        assert_eq!(CchsState::new(ZERO, [1u8; N]), Err(CchsError::ZeroRoot));
        assert_eq!(CchsState::new([1u8; N], ZERO), Err(CchsError::ZeroRoot));
        assert!(CchsState::new([1u8; N], [2u8; N]).is_ok());
    }
}
