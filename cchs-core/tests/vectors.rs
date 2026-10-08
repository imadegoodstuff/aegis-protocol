//! Fixture-driven tests against `evm/test/fixtures/cchs-s-20.json`, the
//! shared ground truth produced by the TypeScript client and executed
//! against the Solidity contract.
//!
//! Run with `cargo test -p cchs-core --features std`.

#![cfg(feature = "std")]

use cchs_core::{
    verify_layer, CchsError, CchsState, LayerSig, H, LAYER_BOTTOM, LAYER_RECOVERY, LAYER_TOP, LEN,
    REC_H,
};
use serde_json::Value;
use sha2::Sha256;

const FIXTURE: &str = include_str!("../../evm/test/fixtures/cchs-s-20.json");

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

fn b32(v: &Value) -> [u8; 32] {
    let bytes = hex_bytes(v.as_str().expect("hex string"));
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn b32_list(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().expect("array").iter().map(b32).collect()
}

struct Layer {
    wots: [[u8; 32]; LEN],
    auth: Vec<[u8; 32]>,
}

impl Layer {
    fn from_json(v: &Value) -> Layer {
        let w = b32_list(&v["wots"]);
        assert_eq!(w.len(), LEN);
        let mut wots = [[0u8; 32]; LEN];
        wots.copy_from_slice(&w);
        Layer { wots, auth: b32_list(&v["auth"]) }
    }
    fn sig(&self) -> LayerSig<'_> {
        LayerSig { wots: &self.wots, auth: &self.auth }
    }
}

#[test]
fn first_op_verifies_both_layers() {
    let f = fixture();
    let root = b32(&f["root"]);
    let bottom0 = b32(&f["bottomRoot0"]);
    let op = &f["ops"][0];
    assert_eq!(op["idx"].as_u64(), Some(0));
    let digest = b32(&op["digest"]);
    let l0 = Layer::from_json(&op["l0"]);
    let l1 = Layer::from_json(&op["l1"]);
    let mut h = Sha256::default();

    // Layer 0: tree 0, leaf 0, message = digest.
    let r0 = verify_layer(&mut h, LAYER_BOTTOM, 0, 0, &digest, &l0.wots, &l0.auth, H);
    assert_eq!(r0, bottom0, "bottom root mismatch");

    // Layer 1: tree 0, leaf = bottom tree index (0), message = R_0.
    let r1 = verify_layer(&mut h, LAYER_TOP, 0, 0, &r0, &l1.wots, &l1.auth, H);
    assert_eq!(r1, root, "top root mismatch");
}

#[test]
fn state_machine_follows_fixture_ops() {
    let f = fixture();
    let root = b32(&f["root"]);
    let rec_root = b32(&f["recRoot"]);
    let bottom0 = b32(&f["bottomRoot0"]);
    let mut state = CchsState::new(root, rec_root).unwrap();
    let mut h = Sha256::default();
    let mut cache: Option<[u8; 32]> = None;

    let ops = f["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 3);
    for (i, op) in ops.iter().enumerate() {
        assert_eq!(op["idx"].as_u64().unwrap(), state.next_idx);
        assert_eq!(op["nonce"].as_u64().unwrap(), state.nonce);
        let digest = b32(&op["digest"]);
        let l0 = Layer::from_json(&op["l0"]);
        let l1 = if op["l1"].is_null() { None } else { Some(Layer::from_json(&op["l1"])) };
        let l1_sig = l1.as_ref().map(|l| l.sig());

        let out = state
            .execute_verify(&mut h, &digest, l0.sig(), l1_sig, cache)
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
    let mut state = CchsState::new(b32(&f["root"]), b32(&f["recRoot"])).unwrap();
    let op = &f["ops"][0];
    let l0 = Layer::from_json(&op["l0"]);
    let mut h = Sha256::default();
    let err = state.execute_verify(&mut h, &b32(&op["digest"]), l0.sig(), None, None).unwrap_err();
    assert_eq!(err, CchsError::MissingTopLayer);
    assert_eq!(state.next_idx, 0, "state untouched on error");
    assert_eq!(state.nonce, 0);
}

#[test]
fn tampered_chain_value_fails() {
    let f = fixture();
    let bottom0 = b32(&f["bottomRoot0"]);
    let op = &f["ops"][0];
    let digest = b32(&op["digest"]);
    let mut l0 = Layer::from_json(&op["l0"]);
    let l1 = Layer::from_json(&op["l1"]);
    l0.wots[5][0] ^= 0x01;
    let mut h = Sha256::default();

    let r0 = verify_layer(&mut h, LAYER_BOTTOM, 0, 0, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);

    // Against the cache.
    let mut state = CchsState::new(b32(&f["root"]), b32(&f["recRoot"])).unwrap();
    let err = state.execute_verify(&mut h, &digest, l0.sig(), None, Some(bottom0)).unwrap_err();
    assert_eq!(err, CchsError::BadSubtreeRoot);

    // Against the top layer (R_0 is wrong, so the top WOTS+ check fails).
    let err = state.execute_verify(&mut h, &digest, l0.sig(), Some(l1.sig()), None).unwrap_err();
    assert_eq!(err, CchsError::BadTopRoot);
    assert_eq!(state.next_idx, 0);
}

#[test]
fn tampered_auth_path_fails() {
    let f = fixture();
    let bottom0 = b32(&f["bottomRoot0"]);
    let op = &f["ops"][1];
    let digest = b32(&op["digest"]);
    let mut l0 = Layer::from_json(&op["l0"]);
    l0.auth[3][31] ^= 0x80;
    let mut h = Sha256::default();
    let r0 = verify_layer(&mut h, LAYER_BOTTOM, 0, 1, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);
}

#[test]
fn wrong_message_fails() {
    let f = fixture();
    let bottom0 = b32(&f["bottomRoot0"]);
    let op = &f["ops"][2];
    let mut digest = b32(&op["digest"]);
    digest[7] ^= 0x10;
    let l0 = Layer::from_json(&op["l0"]);
    let mut h = Sha256::default();
    let r0 = verify_layer(&mut h, LAYER_BOTTOM, 0, 2, &digest, &l0.wots, &l0.auth, H);
    assert_ne!(r0, bottom0);
}

#[test]
fn recovery_vector_verifies() {
    let f = fixture();
    let rec_root = b32(&f["recRoot"]);
    let rec = &f["recovery"];
    assert_eq!(rec["recNonce"].as_u64(), Some(0));
    let digest = b32(&rec["digest"]);
    let layer = Layer::from_json(rec);
    assert_eq!(layer.auth.len(), REC_H);
    let mut h = Sha256::default();

    let r = verify_layer(&mut h, LAYER_RECOVERY, 0, 0, &digest, &layer.wots, &layer.auth, REC_H);
    assert_eq!(r, rec_root, "recovery root mismatch");

    let new_root = b32(&rec["newRoot"]);
    let new_rec_root = b32(&rec["newRecRoot"]);
    let mut state = CchsState::new(b32(&f["root"]), rec_root).unwrap();
    state.next_idx = 3;
    state.nonce = 3;
    let epoch = state
        .recover_verify(&mut h, &digest, new_root, new_rec_root, &layer.wots, &layer.auth)
        .expect("recovery verifies");
    assert_eq!(epoch, 1);
    assert_eq!(state.root, new_root);
    assert_eq!(state.rec_root, new_rec_root);
    assert_eq!(state.next_idx, 0);
    assert_eq!(state.epoch, 1);
    assert_eq!(state.rec_nonce, 1);
    assert_eq!(state.nonce, 3, "tx nonce is not reset by recovery");

    // The same recovery signature cannot be replayed: leaf 1 ≠ leaf 0.
    let err = state
        .recover_verify(&mut h, &digest, new_root, new_rec_root, &layer.wots, &layer.auth)
        .unwrap_err();
    assert_eq!(err, CchsError::BadRecovery);
}

#[test]
fn short_auth_path_is_rejected_without_panic() {
    let f = fixture();
    let mut state = CchsState::new(b32(&f["root"]), b32(&f["recRoot"])).unwrap();
    let op = &f["ops"][0];
    let l0 = Layer::from_json(&op["l0"]);
    let short = LayerSig { wots: &l0.wots, auth: &l0.auth[..H - 1] };
    let mut h = Sha256::default();
    let err = state.execute_verify(&mut h, &b32(&op["digest"]), short, None, None).unwrap_err();
    assert_eq!(err, CchsError::BadLength);
}
