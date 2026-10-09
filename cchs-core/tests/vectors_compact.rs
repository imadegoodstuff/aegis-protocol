//! Fixture-driven tests for the CCHS-C-20 verifier (`cchs_core::compact`)
//! against `evm/test/fixtures/cchs-c-20.json`, produced by the TypeScript
//! client `wallet/src/aegis/cchsCompact.ts`.
//!
//! Run with `cargo test -p cchs-core --features std`.

#![cfg(feature = "std")]

use cchs_core::compact::{
    bottom_root, verify_layer, verify_top_layer, CchsState, Hash, LayerSig, H, LAYER_BYTES, LEN,
    N, REC_H,
};
use cchs_core::{CchsError, Seed, LAYER_BOTTOM, LAYER_RECOVERY, LAYER_TOP};
use serde_json::Value;
use sha2::Sha256;

const FIXTURE: &str = include_str!("../../evm/test/fixtures/cchs-c-20.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn b24(v: &Value) -> Hash {
    let bytes = hex_bytes(v.as_str().expect("hex string"));
    assert_eq!(bytes.len(), N, "expected a 24-byte value");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn b24_list(v: &Value) -> Vec<Hash> {
    v.as_array().expect("array").iter().map(b24).collect()
}

fn seed16(v: &Value) -> Seed {
    let bytes = hex_bytes(v.as_str().expect("hex string"));
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    out
}

/// Public seed of the fixture key tree (carried in every ADRS).
fn seed(f: &Value) -> Seed {
    seed16(&f["seed"])
}

struct Layer {
    wots: [Hash; LEN],
    auth: Vec<Hash>,
}

impl Layer {
    fn from_json(v: &Value) -> Layer {
        let w = b24_list(&v["wots"]);
        assert_eq!(w.len(), LEN);
        let mut wots = [[0u8; N]; LEN];
        wots.copy_from_slice(&w);
        Layer { wots, auth: b24_list(&v["auth"]) }
    }
    fn sig(&self) -> LayerSig<'_> {
        LayerSig { wots: &self.wots, auth: &self.auth }
    }
}

/// One fixture operation (`ops[i]` or `skip.ops[i]`), parsed.
struct Op {
    idx: u64,
    nonce: u64,
    digest: Hash,
    l0: Layer,
    l1: Option<Layer>,
}

impl Op {
    fn from_json(v: &Value) -> Op {
        Op {
            idx: v["idx"].as_u64().expect("idx"),
            nonce: v["nonce"].as_u64().expect("nonce"),
            digest: b24(&v["digest"]),
            l0: Layer::from_json(&v["l0"]),
            l1: if v["l1"].is_null() { None } else { Some(Layer::from_json(&v["l1"])) },
        }
    }
    fn l1_sig(&self) -> Option<LayerSig<'_>> {
        self.l1.as_ref().map(|l| l.sig())
    }
}

/// Fresh state with `ops[0]` applied: subtree 0 registered, `next_idx = 1`.
fn after_first_op(f: &Value, h: &mut Sha256) -> (CchsState, Hash) {
    let mut state = CchsState::new(b24(&f["root"]), b24(&f["recRoot"]), seed(&f)).unwrap();
    let op = Op::from_json(&f["ops"][0]);
    let out = state.execute_verify(h, op.idx, &op.digest, op.l0.sig(), op.l1_sig(), None).unwrap();
    assert!(out.cache_write);
    assert_eq!(out.subtree_root, b24(&f["bottomRoot0"]));
    (state, out.subtree_root)
}

#[test]
fn fixture_declares_c20() {
    let f = fixture();
    assert_eq!(f["paramSet"].as_str(), Some("CCHS-C-20"));
    assert_eq!(f["n"].as_u64(), Some(N as u64));
    assert_eq!(f["w"].as_u64(), Some(256));
    assert_eq!(f["len"].as_u64(), Some(LEN as u64));
    assert_eq!(f["h"].as_u64(), Some(H as u64));
    assert_eq!(f["recH"].as_u64(), Some(REC_H as u64));
    assert_eq!(LAYER_BYTES, 864);
}

#[test]
fn first_op_verifies_both_layers() {
    let f = fixture();
    let root = b24(&f["root"]);
    let bottom0 = b24(&f["bottomRoot0"]);
    let op = &f["ops"][0];
    assert_eq!(op["idx"].as_u64(), Some(0));
    let digest = b24(&op["digest"]);
    let l0 = Layer::from_json(&op["l0"]);
    let l1 = Layer::from_json(&op["l1"]);
    assert_eq!(l0.auth.len(), H);
    assert_eq!(l1.auth.len(), H);
    let mut h = Sha256::default();

    // Layer 0: tree 0, leaf 0, message = digest.
    let r0 = verify_layer(&mut h, &seed(&f), LAYER_BOTTOM, 0, 0, &digest, &l0.wots, &l0.auth, H);
    assert_eq!(r0, bottom0, "bottom root mismatch");

    // Same thing through the host-facing helper.
    let r0b = bottom_root(&mut h, &seed(&f), 0, &digest, l0.sig()).expect("bottom root");
    assert_eq!(r0b, bottom0);

    // Layer 1: tree 0, leaf = bottom tree index (0), message = R_0.
    let r1 = verify_layer(&mut h, &seed(&f), LAYER_TOP, 0, 0, &r0, &l1.wots, &l1.auth, H);
    assert_eq!(r1, root, "top root mismatch");
    verify_top_layer(&mut h, &seed(&f), &root, 0, &bottom0, l1.sig()).expect("top layer verifies");
}

#[test]
fn split_cache_fill_then_cached_ops() {
    // The Solana flow: `cache_subtree` verifies the top layer for
    // (tree_idx, r0) and stores r0; every `execute` then compares against it.
    let f = fixture();
    let root = b24(&f["root"]);
    let bottom0 = b24(&f["bottomRoot0"]);
    let ops = f["ops"].as_array().unwrap();
    let mut h = Sha256::default();

    let l1 = Layer::from_json(&ops[0]["l1"]);
    verify_top_layer(&mut h, &seed(&f), &root, 0, &bottom0, l1.sig()).expect("cache fill");
    let cache: Hash = bottom0;

    let mut state = CchsState::new(root, b24(&f["recRoot"]), seed(&f)).unwrap();
    for (i, op) in ops.iter().enumerate() {
        let digest = b24(&op["digest"]);
        let l0 = Layer::from_json(&op["l0"]);
        let out = state
            .execute_cached(&mut h, i as u64, &digest, l0.sig(), cache)
            .unwrap_or_else(|e| panic!("cached op {i} failed: {e}"));
        assert_eq!(out.idx, i as u64);
        assert_eq!(out.subtree_root, bottom0);
        assert!(!out.cache_write);
        assert_eq!(state.next_idx, i as u64 + 1);
        assert_eq!(state.nonce, i as u64 + 1);
    }
}

#[test]
fn state_machine_follows_fixture_ops() {
    let f = fixture();
    let root = b24(&f["root"]);
    let rec_root = b24(&f["recRoot"]);
    let bottom0 = b24(&f["bottomRoot0"]);
    let mut state = CchsState::new(root, rec_root, seed(&f)).unwrap();
    let mut h = Sha256::default();
    let mut cache: Option<Hash> = None;

    let ops = f["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 3);
    for (i, op) in ops.iter().enumerate() {
        let op = Op::from_json(op);
        assert_eq!(op.idx, state.next_idx);
        assert_eq!(op.nonce, state.nonce);
        assert_eq!(op.l1.is_some(), i == 0, "only ops[0] carries the top layer");

        assert_eq!(CchsState::needs_top_layer(cache), i == 0);
        let out = state
            .execute_verify(&mut h, op.idx, &op.digest, op.l0.sig(), op.l1_sig(), cache)
            .unwrap_or_else(|e| panic!("op {i} failed: {e}"));

        assert_eq!(out.idx, i as u64);
        assert_eq!(out.tree_idx, 0);
        assert_eq!(out.leaf_idx, i as u32);
        assert_eq!(out.subtree_root, bottom0);
        assert_eq!(out.cache_write, i == 0, "only the first op writes the cache");
        if out.cache_write {
            cache = Some(out.subtree_root);
        }
        assert_eq!(state.next_idx, i as u64 + 1);
        assert_eq!(state.nonce, i as u64 + 1);
    }
}

#[test]
fn missing_top_layer_is_rejected() {
    let f = fixture();
    let mut state = CchsState::new(b24(&f["root"]), b24(&f["recRoot"]), seed(&f)).unwrap();
    let op = &f["ops"][0];
    let l0 = Layer::from_json(&op["l0"]);
    let mut h = Sha256::default();
    let err = state.execute_verify(&mut h, 0, &b24(&op["digest"]), l0.sig(), None, None).unwrap_err();
    assert_eq!(err, CchsError::MissingTopLayer);
    // An all-zero cache entry means "absent" for the cached path too.
    let err = state.execute_cached(&mut h, 0, &b24(&op["digest"]), l0.sig(), [0u8; N]).unwrap_err();
    assert_eq!(err, CchsError::MissingTopLayer);
    assert_eq!(state.next_idx, 0, "state untouched on error");
    assert_eq!(state.nonce, 0);
}

// ------------------------------------------------------ signer-chosen index

#[test]
fn skip_within_subtree_then_jump_to_fresh_subtree() {
    let f = fixture();
    let mut h = Sha256::default();
    let (mut state, cache0) = after_first_op(&f, &mut h);
    assert_eq!(state.next_idx, 1);

    // skip.ops[0]: idx 5, nonce 1, cached path (no top layer).
    let op5 = Op::from_json(&f["skip"]["ops"][0]);
    assert_eq!(op5.idx, 5);
    assert_eq!(op5.nonce, state.nonce);
    assert!(op5.l1.is_none());
    let out = state
        .execute_cached(&mut h, op5.idx, &op5.digest, op5.l0.sig(), cache0)
        .expect("skip to leaf 5 on the cached path");
    assert_eq!(out.idx, 5);
    assert_eq!(out.tree_idx, 0);
    assert_eq!(out.leaf_idx, 5);
    assert_eq!(out.subtree_root, cache0);
    assert!(!out.cache_write);
    assert_eq!(state.next_idx, 6);
    assert_eq!(state.nonce, 2);

    // skip.ops[1]: idx 1024, nonce 2, first leaf of subtree 1, carries l1.
    let op1024 = Op::from_json(&f["skip"]["ops"][1]);
    assert_eq!(op1024.idx, 1024);
    assert_eq!(op1024.nonce, state.nonce);
    let l1 = op1024.l1.as_ref().expect("cross-subtree jump carries the top layer");
    let bottom1 = b24(&f["bottomRoot1"]);

    // One-shot path.
    let mut one_shot = state;
    let out = one_shot
        .execute_verify(&mut h, op1024.idx, &op1024.digest, op1024.l0.sig(), Some(l1.sig()), None)
        .expect("cross-subtree jump with top layer");
    assert_eq!(out.idx, 1024);
    assert_eq!(out.tree_idx, 1);
    assert_eq!(out.leaf_idx, 0);
    assert!(out.cache_write, "first use of subtree 1 fills the cache");
    assert_eq!(out.subtree_root, bottom1);
    assert_eq!(one_shot.next_idx, 1025);
    assert_eq!(one_shot.nonce, 3);

    // Split path (Solana): cache_subtree(1, l1, bottomRoot1) then execute.
    let r0 = bottom_root(&mut h, &seed(&f), op1024.idx, &op1024.digest, op1024.l0.sig()).unwrap();
    assert_eq!(r0, bottom1);
    verify_top_layer(&mut h, &seed(&f), &b24(&f["root"]), 1, &bottom1, l1.sig()).expect("cache fill for subtree 1");
    let out = state
        .execute_cached(&mut h, op1024.idx, &op1024.digest, op1024.l0.sig(), bottom1)
        .expect("cached execute at leaf 1024");
    assert_eq!(out.subtree_root, bottom1);
    assert_eq!(state.next_idx, 1025);
    assert_eq!(state.nonce, 3);
}

#[test]
fn index_below_next_idx_is_rejected() {
    let f = fixture();
    let mut h = Sha256::default();
    let (mut state, cache0) = after_first_op(&f, &mut h);

    let op5 = Op::from_json(&f["skip"]["ops"][0]);
    state.execute_cached(&mut h, op5.idx, &op5.digest, op5.l0.sig(), cache0).unwrap();
    assert_eq!(state.next_idx, 6);

    // ops[1] (idx 1) lies in the abandoned range.
    let op1 = Op::from_json(&f["ops"][1]);
    let err = state.execute_cached(&mut h, op1.idx, &op1.digest, op1.l0.sig(), cache0).unwrap_err();
    assert_eq!(err, CchsError::IndexUsed);
    let err = state
        .execute_verify(&mut h, op1.idx, &op1.digest, op1.l0.sig(), None, Some(cache0))
        .unwrap_err();
    assert_eq!(err, CchsError::IndexUsed);

    // Replaying leaf 5 itself is also an index reuse.
    let err = state.execute_cached(&mut h, op5.idx, &op5.digest, op5.l0.sig(), cache0).unwrap_err();
    assert_eq!(err, CchsError::IndexUsed);
    assert_eq!(state.next_idx, 6, "state untouched on error");
    assert_eq!(state.nonce, 2);

    // Direct check, including the upper bound.
    assert_eq!(state.check_idx(5), Err(CchsError::IndexUsed));
    assert_eq!(state.check_idx(6), Ok(()));
    assert_eq!(state.check_idx(1 << 20), Err(CchsError::Exhausted));
}

#[test]
fn jump_to_fresh_subtree_without_top_layer_is_rejected() {
    let f = fixture();
    let mut h = Sha256::default();
    let (mut state, _) = after_first_op(&f, &mut h);

    let op1024 = Op::from_json(&f["skip"]["ops"][1]);
    let err = state
        .execute_verify(&mut h, op1024.idx, &op1024.digest, op1024.l0.sig(), None, None)
        .unwrap_err();
    assert_eq!(err, CchsError::MissingTopLayer);
    // Split path: the cache PDA for subtree 1 is still zero.
    let err = state
        .execute_cached(&mut h, op1024.idx, &op1024.digest, op1024.l0.sig(), [0u8; N])
        .unwrap_err();
    assert_eq!(err, CchsError::MissingTopLayer);
    assert_eq!(state.next_idx, 1);
    assert_eq!(state.nonce, 1);
}

#[test]
fn signature_is_bound_to_its_index() {
    let f = fixture();
    let mut h = Sha256::default();
    let (mut state, cache0) = after_first_op(&f, &mut h);

    // The leaf-5 signature submitted at leaf 6 with the same digest: the
    // bottom root recomputed at position 6 does not match the cache.
    let op5 = Op::from_json(&f["skip"]["ops"][0]);
    let err = state.execute_cached(&mut h, 6, &op5.digest, op5.l0.sig(), cache0).unwrap_err();
    assert_eq!(err, CchsError::BadSubtreeRoot);
    let err = state
        .execute_verify(&mut h, 6, &op5.digest, op5.l0.sig(), None, Some(cache0))
        .unwrap_err();
    assert_eq!(err, CchsError::BadSubtreeRoot);
    assert_eq!(state.next_idx, 1);
}

#[test]
fn redundant_top_layer_on_registered_subtree_is_ignored() {
    let f = fixture();
    let mut h = Sha256::default();
    let (mut state, cache0) = after_first_op(&f, &mut h);

    // ops[1] with ops[0]'s top layer attached: the cache is filled, so the
    // proof is neither verified nor rejected.
    let op0 = Op::from_json(&f["ops"][0]);
    let op1 = Op::from_json(&f["ops"][1]);
    let out = state
        .execute_verify(&mut h, op1.idx, &op1.digest, op1.l0.sig(), op0.l1_sig(), Some(cache0))
        .expect("redundant top layer is ignored");
    assert!(!out.cache_write);
    assert_eq!(out.subtree_root, cache0);
    assert_eq!(state.next_idx, 2);

    // Even a garbage top layer is ignored on the cached path.
    let mut bad = Layer::from_json(&f["ops"][0]["l1"]);
    bad.wots[0][0] ^= 0xFF;
    let op2 = Op::from_json(&f["ops"][2]);
    state
        .execute_verify(&mut h, op2.idx, &op2.digest, op2.l0.sig(), Some(bad.sig()), Some(cache0))
        .expect("top layer not inspected when the subtree is cached");
    assert_eq!(state.next_idx, 3);
}

#[test]
fn tampered_chain_value_fails() {
    let f = fixture();
    let root = b24(&f["root"]);
    let bottom0 = b24(&f["bottomRoot0"]);
    let op = &f["ops"][0];
    let digest = b24(&op["digest"]);
    let mut l0 = Layer::from_json(&op["l0"]);
    let l1 = Layer::from_json(&op["l1"]);
    l0.wots[5][0] ^= 0x01;
    let mut h = Sha256::default();

    let r0 = verify_layer(&mut h, &seed(&f), LAYER_BOTTOM, 0, 0, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);

    // Against the cache.
    let mut state = CchsState::new(root, b24(&f["recRoot"]), seed(&f)).unwrap();
    let err = state.execute_verify(&mut h, 0, &digest, l0.sig(), None, Some(bottom0)).unwrap_err();
    assert_eq!(err, CchsError::BadSubtreeRoot);
    let err = state.execute_cached(&mut h, 0, &digest, l0.sig(), bottom0).unwrap_err();
    assert_eq!(err, CchsError::BadSubtreeRoot);

    // Against the top layer (R_0 is wrong, so the top WOTS+ check fails).
    let err = state.execute_verify(&mut h, 0, &digest, l0.sig(), Some(l1.sig()), None).unwrap_err();
    assert_eq!(err, CchsError::BadTopRoot);
    assert_eq!(state.next_idx, 0);

    // A tampered top-layer chain value cannot register the correct r0 either.
    let mut l1t = Layer::from_json(&op["l1"]);
    l1t.wots[3][0] ^= 0x01;
    let err = verify_top_layer(&mut h, &seed(&f), &root, 0, &bottom0, l1t.sig()).unwrap_err();
    assert_eq!(err, CchsError::BadTopRoot);

    // Nor can a correct top layer register a different r0.
    let mut wrong_r0 = bottom0;
    wrong_r0[0] ^= 0x01;
    let err = verify_top_layer(&mut h, &seed(&f), &root, 0, &wrong_r0, l1.sig()).unwrap_err();
    assert_eq!(err, CchsError::BadTopRoot);
}

#[test]
fn tampered_auth_path_fails() {
    let f = fixture();
    let bottom0 = b24(&f["bottomRoot0"]);
    let op = &f["ops"][1];
    let digest = b24(&op["digest"]);
    let mut l0 = Layer::from_json(&op["l0"]);
    l0.auth[3][23] ^= 0x80;
    let mut h = Sha256::default();
    let r0 = verify_layer(&mut h, &seed(&f), LAYER_BOTTOM, 0, 1, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);
    let r0 = bottom_root(&mut h, &seed(&f), 1, &digest, l0.sig()).unwrap();
    assert_ne!(r0, bottom0);
}

#[test]
fn wrong_message_fails() {
    let f = fixture();
    let bottom0 = b24(&f["bottomRoot0"]);
    let op = &f["ops"][2];
    let mut digest = b24(&op["digest"]);
    digest[7] ^= 0x10;
    let l0 = Layer::from_json(&op["l0"]);
    let mut h = Sha256::default();
    let r0 = verify_layer(&mut h, &seed(&f), LAYER_BOTTOM, 0, 2, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);

    // Same signature at the wrong leaf index is also rejected.
    let digest = b24(&op["digest"]);
    let r0 = bottom_root(&mut h, &seed(&f), 3, &digest, l0.sig()).unwrap();
    assert_ne!(r0, bottom0);
}

#[test]
fn recovery_vector_verifies() {
    let f = fixture();
    let rec_root = b24(&f["recRoot"]);
    let rec = &f["recovery"];
    assert_eq!(rec["recNonce"].as_u64(), Some(0));
    let digest = b24(&rec["digest"]);
    let layer = Layer::from_json(rec);
    assert_eq!(layer.auth.len(), REC_H);
    let mut h = Sha256::default();

    let r = verify_layer(&mut h, &seed(&f), LAYER_RECOVERY, 0, 0, &digest, &layer.wots, &layer.auth, REC_H);
    assert_eq!(r, rec_root, "recovery root mismatch");

    let new_root = b24(&rec["newRoot"]);
    let new_rec_root = b24(&rec["newRecRoot"]);
    let new_seed = seed16(&rec["newSeed"]);
    let mut state = CchsState::new(b24(&f["root"]), rec_root, seed(&f)).unwrap();
    state.next_idx = 3;
    state.nonce = 3;
    let epoch = state
        .recover_verify(&mut h, &digest, new_root, new_rec_root, new_seed, &layer.wots, &layer.auth)
        .expect("recovery verifies");
    assert_eq!(epoch, 1);
    assert_eq!(state.root, new_root);
    assert_eq!(state.rec_root, new_rec_root);
    assert_eq!(state.next_idx, 0);
    assert_eq!(state.epoch, 1);
    assert_eq!(state.rec_nonce, 1);
    assert_eq!(state.nonce, 3, "tx nonce is not reset by recovery");

    // The same recovery signature cannot be replayed: leaf 1 differs from leaf 0.
    let err = state
        .recover_verify(&mut h, &digest, new_root, new_rec_root, new_seed, &layer.wots, &layer.auth)
        .unwrap_err();
    assert_eq!(err, CchsError::BadRecovery);
    assert_eq!(state.rec_nonce, 1, "state untouched on error");
}

#[test]
fn short_auth_path_is_rejected_without_panic() {
    let f = fixture();
    let root = b24(&f["root"]);
    let mut state = CchsState::new(root, b24(&f["recRoot"]), seed(&f)).unwrap();
    let op = &f["ops"][0];
    let l0 = Layer::from_json(&op["l0"]);
    let l1 = Layer::from_json(&op["l1"]);
    let digest = b24(&op["digest"]);
    let short0 = LayerSig { wots: &l0.wots, auth: &l0.auth[..H - 1] };
    let short1 = LayerSig { wots: &l1.wots, auth: &l1.auth[..H - 1] };
    let mut h = Sha256::default();
    let err = state.execute_verify(&mut h, 0, &digest, short0, None, None).unwrap_err();
    assert_eq!(err, CchsError::BadLength);
    let err = bottom_root(&mut h, &seed(&f), 0, &digest, short0).unwrap_err();
    assert_eq!(err, CchsError::BadLength);
    let err = verify_top_layer(&mut h, &seed(&f), &root, 0, &b24(&f["bottomRoot0"]), short1).unwrap_err();
    assert_eq!(err, CchsError::BadLength);
    let err = state.execute_verify(&mut h, 0, &digest, l0.sig(), Some(short1), None).unwrap_err();
    assert_eq!(err, CchsError::BadLength);
    assert_eq!(state.next_idx, 0);
}

#[test]
fn out_of_range_tree_index_is_rejected() {
    let f = fixture();
    let root = b24(&f["root"]);
    let op = &f["ops"][0];
    let l1 = Layer::from_json(&op["l1"]);
    let mut h = Sha256::default();
    let err = verify_top_layer(&mut h, &seed(&f), &root, 1 << H, &b24(&f["bottomRoot0"]), l1.sig()).unwrap_err();
    assert_eq!(err, CchsError::Exhausted);
}
