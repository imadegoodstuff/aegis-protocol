//! Aegis CCHS-S-20 post-quantum smart account for NEAR.
//!
//! Authorization is a WOTS+ (SHA-256, w = 16, 67 chains) signature under a
//! two-layer hypertree of height 10 + 10. The top-layer proof for each bottom
//! subtree is verified once and cached in `cache[(epoch, tree_idx)]`; the
//! next 1023 signatures in that subtree carry only the bottom layer. The
//! verification algorithm lives in `cchs-core` and is byte-exact with
//! `evm/src/AegisCCHS.sol`; this contract only adds the NEAR-specific digest,
//! storage and promise dispatch.
//!
//! The signer chooses the leaf index: `execute(idx, ..)` is accepted for any
//! `idx >= next_idx` (below that: "index used") and sets
//! `next_idx = idx + 1`, abandoning the skipped leaves. The top layer `l1` is
//! required when the subtree of `idx` is not cached yet and ignored when it
//! already is.
//!
//! Message digest (32 bytes, signed by the client):
//!   sha256("AEGIS_CCHS_V1" ‖ "near" ‖ sha256(current_account_id) ‖ nonce u64 BE
//!          ‖ idx u64 BE ‖ sha256(len(receiver_id) u32 BE ‖ receiver_id
//!                              ‖ len(method) u32 BE ‖ method
//!                              ‖ len(args) u32 BE ‖ args ‖ deposit u128 BE))
//! Recovery digest:
//!   sha256("AEGIS_CCHS_RECOVER_V1" ‖ "near" ‖ sha256(current_account_id)
//!          ‖ rec_nonce u64 BE ‖ new_root ‖ new_rec_root ‖ new_seed(16))
//!
//! `seed` is the 16-byte public seed of the key tree (last 16 bytes of every
//! ADRS, spec §2.2); it is stored next to the roots and rotated with them.
//!
//! The variable-length fields of the inner call hash are length-prefixed so
//! that `(receiver_id, method, args)` cannot be re-split into a different call
//! with the same digest.
//!
//! `execute` and `recover` take Borsh-encoded arguments (`Vec<[u8; 32]>` for
//! chain values and auth paths); `new` and the views use JSON.
//!
//! Spec: ../../CCHS.spec.md

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, PanicOnDefault, Promise};

use cchs_core::{CchsState, LayerSig, Seed, Sha256, H, LEN, REC_H, SEED_BYTES};

pub const DOMAIN_EXECUTE: &[u8] = b"AEGIS_CCHS_V1";
pub const DOMAIN_RECOVER: &[u8] = b"AEGIS_CCHS_RECOVER_V1";
pub const CHAIN_TAG: &[u8] = b"near";

// ------------------------------------------------------------------- hash

/// SHA-256 through the `sha256` host function. Input is accumulated in a
/// buffer and hashed in one host call per digest.
pub struct NearSha256 {
    buf: Vec<u8>,
}

impl Default for NearSha256 {
    fn default() -> Self {
        NearSha256 { buf: Vec::with_capacity(32 + 32 * LEN) }
    }
}

impl Sha256 for NearSha256 {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn finish(&mut self) -> [u8; 32] {
        let out = env::sha256_array(&self.buf);
        self.buf.clear();
        out
    }
}

// ------------------------------------------------------------------ types

/// One layer of a signature: 67 chain values and the authentication path
/// (10 siblings for the hypertree layers, 8 for the recovery tree).
#[near(serializers = [borsh])]
pub struct LayerSigArg {
    pub wots: Vec<[u8; 32]>,
    pub auth: Vec<[u8; 32]>,
}

#[near(serializers = [json])]
pub struct StateView {
    pub root: Base64VecU8,
    pub rec_root: Base64VecU8,
    pub seed: Base64VecU8,
    pub epoch: U64,
    pub next_idx: U64,
    pub nonce: U64,
    pub rec_nonce: U64,
}

// --------------------------------------------------------------- contract

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AegisCchs {
    root: [u8; 32],
    rec_root: [u8; 32],
    /// Public seed of the current key tree (in every ADRS).
    seed: Seed,
    epoch: u64,
    /// Lowest leaf index still available; every leaf below it is consumed
    /// or abandoned.
    next_idx: u64,
    nonce: u64,
    rec_nonce: u64,
    /// cachedRoot[(epoch, bottomTreeIdx)] = verified bottom subtree root.
    cache: LookupMap<(u64, u64), [u8; 32]>,
}

#[near]
impl AegisCchs {
    /// Deploy-time initializer. `root` and `rec_root` are 32-byte base64,
    /// `seed` is the 16-byte public seed of the key tree.
    #[init]
    pub fn new(root: Base64VecU8, rec_root: Base64VecU8, seed: Base64VecU8) -> Self {
        let root = b32(&root.0, "root");
        let rec_root = b32(&rec_root.0, "rec_root");
        let seed = b16(&seed.0, "seed");
        let st = CchsState::new(root, rec_root, seed).unwrap_or_else(|e| env::panic_str(e.as_str()));
        Self {
            root: st.root,
            rec_root: st.rec_root,
            seed: st.seed,
            epoch: 0,
            next_idx: 0,
            nonce: 0,
            rec_nonce: 0,
            cache: LookupMap::new(b"c"),
        }
    }

    /// Call `receiver_id.method(args)` with `deposit` yoctoNEAR and `gas`,
    /// authorized by a CCHS signature on the digest of
    /// `(this account, nonce, idx, receiver_id, method, args, deposit)`.
    /// `idx` is chosen by the signer and must be `>= next_idx`; on success
    /// `next_idx = idx + 1`. `l1` is required on the first use of the bottom
    /// subtree of `idx` and ignored once that subtree is cached.
    pub fn execute(
        &mut self,
        #[serializer(borsh)] idx: u64,
        #[serializer(borsh)] l0: LayerSigArg,
        #[serializer(borsh)] l1: Option<LayerSigArg>,
        #[serializer(borsh)] receiver_id: AccountId,
        #[serializer(borsh)] method: String,
        #[serializer(borsh)] args: Vec<u8>,
        #[serializer(borsh)] deposit: u128,
        #[serializer(borsh)] gas: u64,
    ) -> Promise {
        let mut state = self.state();
        // Index discipline first, before any hashing.
        state.check_idx(idx).unwrap_or_else(|e| env::panic_str(e.as_str()));
        let tree_idx = idx >> H;

        let mut h = NearSha256::default();
        let digest = execute_digest(&mut h, state.nonce, idx, &receiver_id, &method, &args, deposit);

        let l0_w = wots_arr(&l0.wots);
        check_auth(&l0.auth, H);
        let l0_sig = LayerSig { wots: &l0_w, auth: &l0.auth };

        let l1_w = l1.as_ref().map(|l| wots_arr(&l.wots));
        let l1_sig = match (&l1, &l1_w) {
            (Some(l), Some(w)) => {
                check_auth(&l.auth, H);
                Some(LayerSig { wots: w, auth: &l.auth })
            }
            _ => None,
        };

        let key = (state.epoch, tree_idx);
        let cached = self.cache.get(&key).copied();

        let outcome = state
            .execute_verify(&mut h, idx, &digest, l0_sig, l1_sig, cached)
            .unwrap_or_else(|e| env::panic_str(e.as_str()));

        self.store(&state);
        if outcome.cache_write {
            self.cache.insert(key, outcome.subtree_root);
            near_sdk::log!("subtree_cached epoch={} tree_idx={}", state.epoch, tree_idx);
        }
        near_sdk::log!("executed idx={} receiver={} method={}", idx, receiver_id, method);

        Promise::new(receiver_id).function_call(
            method,
            args,
            NearToken::from_yoctonear(deposit),
            Gas::from_gas(gas),
        )
    }

    /// Rotate the public key (both roots and the seed), authorized by the
    /// recovery tree at leaf `rec_nonce`. Resets `next_idx` and bumps
    /// `epoch`, which logically clears the subtree cache.
    pub fn recover(
        &mut self,
        #[serializer(borsh)] new_root: [u8; 32],
        #[serializer(borsh)] new_rec_root: [u8; 32],
        #[serializer(borsh)] new_seed: [u8; 16],
        #[serializer(borsh)] wots: Vec<[u8; 32]>,
        #[serializer(borsh)] auth: Vec<[u8; 32]>,
    ) {
        let mut state = self.state();
        let mut h = NearSha256::default();
        let digest = recover_digest(&mut h, state.rec_nonce, &new_root, &new_rec_root, &new_seed);

        let w = wots_arr(&wots);
        check_auth(&auth, REC_H);

        let epoch = state
            .recover_verify(&mut h, &digest, new_root, new_rec_root, new_seed, &w, &auth)
            .unwrap_or_else(|e| env::panic_str(e.as_str()));
        self.store(&state);
        near_sdk::log!("recovered epoch={}", epoch);
    }

    // ---- views ----

    pub fn get_state(&self) -> StateView {
        StateView {
            root: Base64VecU8(self.root.to_vec()),
            rec_root: Base64VecU8(self.rec_root.to_vec()),
            seed: Base64VecU8(self.seed.to_vec()),
            epoch: U64(self.epoch),
            next_idx: U64(self.next_idx),
            nonce: U64(self.nonce),
            rec_nonce: U64(self.rec_nonce),
        }
    }

    /// Whether an `execute` at leaf `next_idx` must include the top layer.
    pub fn needs_top_layer(&self) -> bool {
        self.needs_top_layer_at(U64(self.next_idx))
    }

    /// Whether an `execute` at leaf `idx` must include the top layer.
    pub fn needs_top_layer_at(&self, idx: U64) -> bool {
        let key = (self.epoch, idx.0 >> H);
        CchsState::needs_top_layer(self.cache.get(&key).copied())
    }

    /// Digest the client must sign for an `execute` at leaf `next_idx`.
    pub fn next_digest(
        &self,
        receiver_id: AccountId,
        method: String,
        args: Base64VecU8,
        deposit: U128,
    ) -> Base64VecU8 {
        self.digest_at(U64(self.next_idx), receiver_id, method, args, deposit)
    }

    /// Digest the client must sign for an `execute` at leaf `idx`
    /// (`idx >= next_idx`) with the current nonce.
    pub fn digest_at(
        &self,
        idx: U64,
        receiver_id: AccountId,
        method: String,
        args: Base64VecU8,
        deposit: U128,
    ) -> Base64VecU8 {
        let mut h = NearSha256::default();
        let d = execute_digest(&mut h, self.nonce, idx.0, &receiver_id, &method, &args.0, deposit.0);
        Base64VecU8(d.to_vec())
    }

    /// Digest the client must sign for the next `recover`.
    pub fn next_recovery_digest(
        &self,
        new_root: Base64VecU8,
        new_rec_root: Base64VecU8,
        new_seed: Base64VecU8,
    ) -> Base64VecU8 {
        let mut h = NearSha256::default();
        let d = recover_digest(
            &mut h,
            self.rec_nonce,
            &b32(&new_root.0, "new_root"),
            &b32(&new_rec_root.0, "new_rec_root"),
            &b16(&new_seed.0, "new_seed"),
        );
        Base64VecU8(d.to_vec())
    }
}

impl AegisCchs {
    fn state(&self) -> CchsState {
        CchsState {
            root: self.root,
            rec_root: self.rec_root,
            seed: self.seed,
            epoch: self.epoch,
            next_idx: self.next_idx,
            nonce: self.nonce,
            rec_nonce: self.rec_nonce,
        }
    }

    fn store(&mut self, s: &CchsState) {
        self.root = s.root;
        self.rec_root = s.rec_root;
        self.seed = s.seed;
        self.epoch = s.epoch;
        self.next_idx = s.next_idx;
        self.nonce = s.nonce;
        self.rec_nonce = s.rec_nonce;
    }
}

// ---------------------------------------------------------------- digests

/// `sha256("AEGIS_CCHS_V1" ‖ "near" ‖ sha256(current_account_id) ‖ nonce BE ‖ idx BE ‖ inner)`
/// with `inner = sha256(len ‖ receiver_id ‖ len ‖ method ‖ len ‖ args ‖ deposit u128 BE)`.
pub fn execute_digest(
    h: &mut NearSha256,
    nonce: u64,
    idx: u64,
    receiver_id: &AccountId,
    method: &str,
    args: &[u8],
    deposit: u128,
) -> [u8; 32] {
    let receiver = receiver_id.as_str().as_bytes();
    h.update(&(receiver.len() as u32).to_be_bytes());
    h.update(receiver);
    h.update(&(method.len() as u32).to_be_bytes());
    h.update(method.as_bytes());
    h.update(&(args.len() as u32).to_be_bytes());
    h.update(args);
    h.update(&deposit.to_be_bytes());
    let inner = h.finish();

    let self_id = account_id_hash(h);

    h.update(DOMAIN_EXECUTE);
    h.update(CHAIN_TAG);
    h.update(&self_id);
    h.update(&nonce.to_be_bytes());
    h.update(&idx.to_be_bytes());
    h.update(&inner);
    h.finish()
}

/// `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "near" ‖ sha256(current_account_id) ‖ rec_nonce BE ‖ new_root ‖ new_rec_root ‖ new_seed)`
pub fn recover_digest(
    h: &mut NearSha256,
    rec_nonce: u64,
    new_root: &[u8; 32],
    new_rec_root: &[u8; 32],
    new_seed: &Seed,
) -> [u8; 32] {
    let self_id = account_id_hash(h);
    h.update(DOMAIN_RECOVER);
    h.update(CHAIN_TAG);
    h.update(&self_id);
    h.update(&rec_nonce.to_be_bytes());
    h.update(new_root);
    h.update(new_rec_root);
    h.update(new_seed);
    h.finish()
}

fn account_id_hash(h: &mut NearSha256) -> [u8; 32] {
    h.update(env::current_account_id().as_str().as_bytes());
    h.finish()
}

// ---------------------------------------------------------------- helpers

fn b32(v: &[u8], what: &str) -> [u8; 32] {
    if v.len() != 32 {
        env::panic_str(&format!("{what}: expected 32 bytes, got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    out
}

fn b16(v: &[u8], what: &str) -> Seed {
    if v.len() != SEED_BYTES {
        env::panic_str(&format!("{what}: expected {SEED_BYTES} bytes, got {}", v.len()));
    }
    let mut out = [0u8; SEED_BYTES];
    out.copy_from_slice(v);
    out
}

fn wots_arr(v: &[[u8; 32]]) -> [[u8; 32]; LEN] {
    if v.len() != LEN {
        env::panic_str(&format!("wots: expected {LEN} chain values, got {}", v.len()));
    }
    let mut out = [[0u8; 32]; LEN];
    out.copy_from_slice(v);
    out
}

fn check_auth(auth: &[[u8; 32]], height: usize) {
    if auth.len() != height {
        env::panic_str(&format!("auth: expected {height} siblings, got {}", auth.len()));
    }
}

// ------------------------------------------------------------------ tests

/// The shared fixture digests bind the EVM chain id and account, so the
/// signature vectors cannot be replayed through this contract's digest; the
/// verifier itself is covered by `cchs-core/tests/vectors.rs`. These tests
/// cover the contract-level index discipline and the index-taking views.
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn setup() -> AegisCchs {
        let ctx = VMContextBuilder::new()
            .current_account_id("alice.near".parse().unwrap())
            .predecessor_account_id("relayer.near".parse().unwrap())
            .build();
        testing_env!(ctx);
        AegisCchs::new(
            Base64VecU8(vec![0x11u8; 32]),
            Base64VecU8(vec![0x22u8; 32]),
            Base64VecU8(vec![0x33u8; 16]),
        )
    }

    fn zero_layer(height: usize) -> LayerSigArg {
        LayerSigArg { wots: vec![[0u8; 32]; LEN], auth: vec![[0u8; 32]; height] }
    }

    fn receiver() -> AccountId {
        "bob.near".parse().unwrap()
    }

    #[test]
    fn digest_at_binds_the_index() {
        let c = setup();
        let next = c.next_digest(receiver(), "ping".into(), Base64VecU8(vec![1, 2, 3]), U128(5));
        let at0 = c.digest_at(U64(0), receiver(), "ping".into(), Base64VecU8(vec![1, 2, 3]), U128(5));
        let at5 = c.digest_at(U64(5), receiver(), "ping".into(), Base64VecU8(vec![1, 2, 3]), U128(5));
        assert_eq!(next.0, at0.0, "next_digest is digest_at(next_idx)");
        assert_ne!(at0.0, at5.0, "the leaf index is part of the digest");
        assert_eq!(at5.0.len(), 32);
    }

    #[test]
    fn needs_top_layer_at_reports_uncached_subtrees() {
        let mut c = setup();
        assert!(c.needs_top_layer());
        assert!(c.needs_top_layer_at(U64(5)));
        assert!(c.needs_top_layer_at(U64(1024)));

        // Register subtree 0 directly in storage.
        c.cache.insert((0, 0), [0x33u8; 32]);
        assert!(!c.needs_top_layer());
        assert!(!c.needs_top_layer_at(U64(5)));
        assert!(!c.needs_top_layer_at(U64(1023)));
        assert!(c.needs_top_layer_at(U64(1024)), "subtree 1 is still uncached");
    }

    #[test]
    #[should_panic(expected = "index used")]
    fn index_below_next_idx_is_rejected_before_hashing() {
        let mut c = setup();
        c.next_idx = 6;
        // Deliberately malformed layer: the index check must fire first.
        let bad = LayerSigArg { wots: vec![], auth: vec![] };
        let _ = c.execute(5, bad, None, receiver(), "ping".into(), vec![], 0, 5_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "exhausted")]
    fn index_at_capacity_is_rejected() {
        let mut c = setup();
        let bad = LayerSigArg { wots: vec![], auth: vec![] };
        let _ = c.execute(1 << 20, bad, None, receiver(), "ping".into(), vec![], 0, 5_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "missing top layer")]
    fn jump_to_uncached_subtree_without_top_layer_is_rejected() {
        let mut c = setup();
        let _ = c.execute(1024, zero_layer(H), None, receiver(), "ping".into(), vec![], 0, 5_000_000_000_000);
    }
}
