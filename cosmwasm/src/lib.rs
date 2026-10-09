//! Aegis CCHS-S-20 post-quantum smart account for CosmWasm chains.
//!
//! Authorization is a WOTS+ (SHA-256, w = 16, 67 chains) signature under a
//! two-layer hypertree of height 10 + 10. The top-layer proof for each bottom
//! subtree is verified once and cached in `CACHE[(epoch, tree_idx)]`; the
//! next 1023 signatures in that subtree carry only the bottom layer. The
//! verification algorithm lives in `cchs-core` and is byte-exact with
//! `evm/src/AegisCCHS.sol`; this contract only adds the CosmWasm-specific
//! digest, storage and message dispatch.
//!
//! The signer chooses the leaf index: `Execute { idx, .. }` is accepted for
//! any `idx >= next_idx` (below that: `IndexUsed`) and sets
//! `next_idx = idx + 1`, abandoning the skipped leaves. The top layer `l1` is
//! required when the subtree of `idx` is not cached yet and ignored when it
//! already is.
//!
//! Message digest (32 bytes, signed by the client):
//!   sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ nonce u64 BE
//!          ‖ idx u64 BE ‖ sha256(to_json_binary(msgs)))
//! Recovery digest:
//!   sha256("AEGIS_CCHS_RECOVER_V1" ‖ "cosmwasm" ‖ contract_address_utf8
//!          ‖ rec_nonce u64 BE ‖ new_root ‖ new_rec_root ‖ new_seed(16))
//!
//! `seed` is the 16-byte public seed of the key tree (last 16 bytes of every
//! ADRS, spec §2.2); it is stored next to the roots and rotated with them.
//!
//! `contract_address_utf8` is the bech32 string of `env.contract.address`,
//! which also binds the chain prefix (`osmo1…`, `neutron1…`, …).
//!
//! Spec: ../../CCHS.spec.md

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    entry_point, to_json_binary, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response,
    StdResult,
};
use cw_storage_plus::{Item, Map};
use thiserror::Error;

use cchs_core::{CchsError, CchsState, LayerSig, Seed, Sha256 as CchsHash, H, LEN, REC_H, SEED_BYTES};

/// Hasher type: pure-Rust SHA-256 (compiles to wasm, no host function needed).
type Hasher = sha2::Sha256;

pub const DOMAIN_EXECUTE: &[u8] = b"AEGIS_CCHS_V1";
pub const DOMAIN_RECOVER: &[u8] = b"AEGIS_CCHS_RECOVER_V1";
pub const CHAIN_TAG: &[u8] = b"cosmwasm";

// ---------------------------------------------------------------- storage

const STATE: Item<State> = Item::new("state");
/// cachedRoot[(epoch, bottomTreeIdx)] = verified bottom subtree root.
const CACHE: Map<(u64, u64), Binary> = Map::new("cache");

#[cw_serde]
pub struct State {
    /// Top-layer tree root (32 bytes). Rotatable only via `Recover`.
    pub root: Binary,
    /// Recovery tree root (32 bytes, single layer, height 8).
    pub rec_root: Binary,
    /// Public seed of the current key tree (16 bytes, in every ADRS).
    pub seed: Binary,
    /// Increments on every recovery; namespaces the cache.
    pub epoch: u64,
    /// Lowest leaf index still available in [0, 2^20); every leaf below it
    /// is consumed or abandoned.
    pub next_idx: u64,
    /// Transaction nonce bound into every message digest.
    pub nonce: u64,
    /// Next unused recovery leaf in [0, 256).
    pub rec_nonce: u64,
}

// --------------------------------------------------------------- messages

#[cw_serde]
pub struct LayerSigMsg {
    /// 67 chain values, 32 bytes each.
    pub wots: Vec<Binary>,
    /// Authentication path, leaf → root: 10 siblings (8 for recovery).
    pub auth: Vec<Binary>,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub root: Binary,
    pub rec_root: Binary,
    /// 16-byte public seed of the key tree.
    pub seed: Binary,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Dispatch `msgs` from the contract, authorized by a CCHS signature on
    /// the digest of `(contract, nonce, idx, msgs)`. `idx` is chosen by the
    /// signer and must be `>= next_idx`; on success `next_idx = idx + 1`.
    /// `l1` is required on the first use of the bottom subtree of `idx`
    /// (see `QueryMsg::NeedsTopLayerAt`) and ignored once it is cached.
    Execute {
        idx: u64,
        l0: LayerSigMsg,
        l1: Option<LayerSigMsg>,
        msgs: Vec<CosmosMsg>,
    },
    /// Rotate the public key (both roots and the seed), authorized by the
    /// recovery tree at leaf `rec_nonce`.
    Recover {
        new_root: Binary,
        new_rec_root: Binary,
        new_seed: Binary,
        wots: Vec<Binary>,
        auth: Vec<Binary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(State)]
    State {},
    /// Digest the client must sign for an `Execute` of `msgs` at leaf
    /// `next_idx` with the current nonce.
    #[returns(Binary)]
    NextDigest { msgs: Vec<CosmosMsg> },
    /// Digest the client must sign for an `Execute` of `msgs` at leaf `idx`
    /// (`idx >= next_idx`) with the current nonce.
    #[returns(Binary)]
    DigestAt { idx: u64, msgs: Vec<CosmosMsg> },
    /// Digest the client must sign for the next `Recover`.
    #[returns(Binary)]
    NextRecoveryDigest { new_root: Binary, new_rec_root: Binary, new_seed: Binary },
    /// Whether an `Execute` at leaf `next_idx` must include the top layer.
    #[returns(bool)]
    NeedsTopLayer {},
    /// Whether an `Execute` at leaf `idx` must include the top layer.
    #[returns(bool)]
    NeedsTopLayerAt { idx: u64 },
}

// ----------------------------------------------------------------- errors

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] cosmwasm_std::StdError),
    #[error("signature capacity exhausted")]
    Exhausted,
    #[error("leaf index already used or abandoned")]
    IndexUsed,
    #[error("subtree not cached and no top-layer proof supplied")]
    MissingTopLayer,
    #[error("bottom root does not match cached subtree root")]
    BadSubtreeRoot,
    #[error("top-layer path does not reach root")]
    BadTopRoot,
    #[error("recovery path does not reach recovery root")]
    BadRecovery,
    #[error("zero root")]
    ZeroRoot,
    #[error("wrong length: expected {expected} bytes or items, got {got}")]
    BadLength { expected: usize, got: usize },
}

impl From<CchsError> for ContractError {
    fn from(e: CchsError) -> Self {
        match e {
            CchsError::Exhausted => ContractError::Exhausted,
            CchsError::IndexUsed => ContractError::IndexUsed,
            CchsError::MissingTopLayer => ContractError::MissingTopLayer,
            CchsError::BadSubtreeRoot => ContractError::BadSubtreeRoot,
            CchsError::BadTopRoot => ContractError::BadTopRoot,
            CchsError::BadRecovery => ContractError::BadRecovery,
            CchsError::ZeroRoot => ContractError::ZeroRoot,
            CchsError::BadLength => ContractError::BadLength { expected: H, got: 0 },
        }
    }
}

// ----------------------------------------------------------- entry points

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let root = b32(&msg.root)?;
    let rec_root = b32(&msg.rec_root)?;
    let seed = b16(&msg.seed)?;
    let state = CchsState::new(root, rec_root, seed)?;
    STATE.save(deps.storage, &to_stored(&state))?;
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("root", msg.root.to_base64())
        .add_attribute("rec_root", msg.rec_root.to_base64())
        .add_attribute("seed", msg.seed.to_base64()))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Execute { idx, l0, l1, msgs } => exec_execute(deps, env, idx, l0, l1, msgs),
        ExecuteMsg::Recover { new_root, new_rec_root, new_seed, wots, auth } => {
            exec_recover(deps, env, new_root, new_rec_root, new_seed, wots, auth)
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::State {} => to_json_binary(&STATE.load(deps.storage)?),
        QueryMsg::NextDigest { msgs } => {
            let st = STATE.load(deps.storage)?;
            let d = execute_digest(&env, st.nonce, st.next_idx, &msgs)?;
            to_json_binary(&Binary::from(d.to_vec()))
        }
        QueryMsg::DigestAt { idx, msgs } => {
            let st = STATE.load(deps.storage)?;
            let d = execute_digest(&env, st.nonce, idx, &msgs)?;
            to_json_binary(&Binary::from(d.to_vec()))
        }
        QueryMsg::NextRecoveryDigest { new_root, new_rec_root, new_seed } => {
            let st = STATE.load(deps.storage)?;
            let d = recover_digest(&env, st.rec_nonce, new_root.as_slice(), new_rec_root.as_slice(), new_seed.as_slice());
            to_json_binary(&Binary::from(d.to_vec()))
        }
        QueryMsg::NeedsTopLayer {} => {
            let st = STATE.load(deps.storage)?;
            to_json_binary(&needs_top_layer_at(deps, &st, st.next_idx)?)
        }
        QueryMsg::NeedsTopLayerAt { idx } => {
            let st = STATE.load(deps.storage)?;
            to_json_binary(&needs_top_layer_at(deps, &st, idx)?)
        }
    }
}

fn needs_top_layer_at(deps: Deps, st: &State, idx: u64) -> StdResult<bool> {
    let cached = CACHE.may_load(deps.storage, (st.epoch, idx >> H))?;
    let cached = cached.and_then(|b| b32(&b).ok());
    Ok(CchsState::needs_top_layer(cached))
}

// --------------------------------------------------------------- handlers

fn exec_execute(
    deps: DepsMut,
    env: Env,
    idx: u64,
    l0: LayerSigMsg,
    l1: Option<LayerSigMsg>,
    msgs: Vec<CosmosMsg>,
) -> Result<Response, ContractError> {
    let stored = STATE.load(deps.storage)?;
    let mut state = from_stored(&stored)?;
    // Index discipline first, before any hashing.
    state.check_idx(idx)?;
    let tree_idx = idx >> H;

    let digest = execute_digest(&env, state.nonce, idx, &msgs)?;

    let l0 = parse_layer(&l0, H)?;
    let l1 = match &l1 {
        Some(l) => Some(parse_layer(l, H)?),
        None => None,
    };
    let l1_sig = l1.as_ref().map(|l| l.sig());

    let key = (state.epoch, tree_idx);
    let cached = match CACHE.may_load(deps.storage, key)? {
        Some(b) => Some(b32(&b)?),
        None => None,
    };

    let mut h = Hasher::default();
    let outcome = state.execute_verify(&mut h, idx, &digest, l0.sig(), l1_sig, cached)?;

    STATE.save(deps.storage, &to_stored(&state))?;
    let mut resp = Response::new()
        .add_attribute("action", "execute")
        .add_attribute("idx", idx.to_string())
        .add_attribute("msgs", msgs.len().to_string());
    if outcome.cache_write {
        CACHE.save(deps.storage, key, &Binary::from(outcome.subtree_root.to_vec()))?;
        resp = resp
            .add_attribute("subtree_cached", tree_idx.to_string())
            .add_attribute("epoch", state.epoch.to_string());
    }
    Ok(resp.add_messages(msgs))
}

fn exec_recover(
    deps: DepsMut,
    env: Env,
    new_root: Binary,
    new_rec_root: Binary,
    new_seed: Binary,
    wots: Vec<Binary>,
    auth: Vec<Binary>,
) -> Result<Response, ContractError> {
    let stored = STATE.load(deps.storage)?;
    let mut state = from_stored(&stored)?;

    let new_root_b = b32(&new_root)?;
    let new_rec_root_b = b32(&new_rec_root)?;
    let new_seed_b = b16(&new_seed)?;
    let layer = parse_layer(&LayerSigMsg { wots, auth }, REC_H)?;

    let digest = recover_digest(&env, state.rec_nonce, &new_root_b, &new_rec_root_b, &new_seed_b);

    let mut h = Hasher::default();
    let epoch = state.recover_verify(
        &mut h,
        &digest,
        new_root_b,
        new_rec_root_b,
        new_seed_b,
        &layer.wots,
        &layer.auth,
    )?;
    STATE.save(deps.storage, &to_stored(&state))?;

    Ok(Response::new()
        .add_attribute("action", "recover")
        .add_attribute("epoch", epoch.to_string())
        .add_attribute("root", new_root.to_base64())
        .add_attribute("rec_root", new_rec_root.to_base64())
        .add_attribute("seed", new_seed.to_base64()))
}

// ---------------------------------------------------------------- digests

/// `sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address ‖ nonce BE ‖ idx BE ‖ sha256(to_json_binary(msgs)))`
pub fn execute_digest(env: &Env, nonce: u64, idx: u64, msgs: &[CosmosMsg]) -> StdResult<[u8; 32]> {
    let encoded = to_json_binary(msgs)?;
    let mut h = Hasher::default();
    CchsHash::update(&mut h, encoded.as_slice());
    let inner = CchsHash::finish(&mut h);

    CchsHash::update(&mut h, DOMAIN_EXECUTE);
    CchsHash::update(&mut h, CHAIN_TAG);
    CchsHash::update(&mut h, env.contract.address.as_bytes());
    CchsHash::update(&mut h, &nonce.to_be_bytes());
    CchsHash::update(&mut h, &idx.to_be_bytes());
    CchsHash::update(&mut h, &inner);
    Ok(CchsHash::finish(&mut h))
}

/// `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "cosmwasm" ‖ contract_address ‖ rec_nonce BE ‖ new_root ‖ new_rec_root ‖ new_seed)`
pub fn recover_digest(
    env: &Env,
    rec_nonce: u64,
    new_root: &[u8],
    new_rec_root: &[u8],
    new_seed: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::default();
    CchsHash::update(&mut h, DOMAIN_RECOVER);
    CchsHash::update(&mut h, CHAIN_TAG);
    CchsHash::update(&mut h, env.contract.address.as_bytes());
    CchsHash::update(&mut h, &rec_nonce.to_be_bytes());
    CchsHash::update(&mut h, new_root);
    CchsHash::update(&mut h, new_rec_root);
    CchsHash::update(&mut h, new_seed);
    CchsHash::finish(&mut h)
}

// ---------------------------------------------------------------- helpers

/// Owned, length-checked layer signature.
struct OwnedLayer {
    wots: [[u8; 32]; LEN],
    auth: Vec<[u8; 32]>,
}

impl OwnedLayer {
    fn sig(&self) -> LayerSig<'_> {
        LayerSig { wots: &self.wots, auth: &self.auth }
    }
}

fn parse_layer(l: &LayerSigMsg, height: usize) -> Result<OwnedLayer, ContractError> {
    if l.wots.len() != LEN {
        return Err(ContractError::BadLength { expected: LEN, got: l.wots.len() });
    }
    if l.auth.len() != height {
        return Err(ContractError::BadLength { expected: height, got: l.auth.len() });
    }
    let mut wots = [[0u8; 32]; LEN];
    for (i, b) in l.wots.iter().enumerate() {
        wots[i] = b32(b)?;
    }
    let mut auth = Vec::with_capacity(height);
    for b in l.auth.iter() {
        auth.push(b32(b)?);
    }
    Ok(OwnedLayer { wots, auth })
}

fn b32(b: &Binary) -> Result<[u8; 32], ContractError> {
    let s = b.as_slice();
    if s.len() != 32 {
        return Err(ContractError::BadLength { expected: 32, got: s.len() });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

fn b16(b: &Binary) -> Result<Seed, ContractError> {
    let s = b.as_slice();
    if s.len() != SEED_BYTES {
        return Err(ContractError::BadLength { expected: SEED_BYTES, got: s.len() });
    }
    let mut out = [0u8; SEED_BYTES];
    out.copy_from_slice(s);
    Ok(out)
}

fn to_stored(s: &CchsState) -> State {
    State {
        root: Binary::from(s.root.to_vec()),
        rec_root: Binary::from(s.rec_root.to_vec()),
        seed: Binary::from(s.seed.to_vec()),
        epoch: s.epoch,
        next_idx: s.next_idx,
        nonce: s.nonce,
        rec_nonce: s.rec_nonce,
    }
}

fn from_stored(s: &State) -> Result<CchsState, ContractError> {
    Ok(CchsState {
        root: b32(&s.root)?,
        rec_root: b32(&s.rec_root)?,
        seed: b16(&s.seed)?,
        epoch: s.epoch,
        next_idx: s.next_idx,
        nonce: s.nonce,
        rec_nonce: s.rec_nonce,
    })
}

// ------------------------------------------------------------------ tests

/// The shared fixture digests bind the EVM chain id and account, so the
/// signature vectors cannot be replayed through this contract's digest; the
/// verifier itself is covered by `cchs-core/tests/vectors.rs`. These tests
/// cover the contract-level index discipline and the index-taking queries.
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier};
    use cosmwasm_std::{from_json, BankMsg, Coin, MemoryStorage, OwnedDeps, Uint128};

    type TestDeps = OwnedDeps<MemoryStorage, MockApi, MockQuerier>;

    fn zero_layer(height: usize) -> LayerSigMsg {
        LayerSigMsg {
            wots: vec![Binary::from(vec![0u8; 32]); LEN],
            auth: vec![Binary::from(vec![0u8; 32]); height],
        }
    }

    fn setup() -> (TestDeps, Env) {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("deployer"), &[]);
        let msg = InstantiateMsg {
            root: Binary::from(vec![0x11u8; 32]),
            rec_root: Binary::from(vec![0x22u8; 32]),
            seed: Binary::from(vec![0x33u8; 16]),
        };
        instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();
        (deps, env)
    }

    fn sample_msgs() -> Vec<CosmosMsg> {
        vec![CosmosMsg::Bank(BankMsg::Send {
            to_address: "recipient".into(),
            amount: vec![Coin { denom: "uatom".into(), amount: Uint128::new(7) }],
        })]
    }

    fn set_next_idx(deps: &mut TestDeps, next_idx: u64) {
        let mut st = STATE.load(&deps.storage).unwrap();
        st.next_idx = next_idx;
        STATE.save(&mut deps.storage, &st).unwrap();
    }

    #[test]
    fn digest_at_binds_the_index() {
        let (deps, env) = setup();
        let msgs = sample_msgs();
        let next: Binary =
            from_json(query(deps.as_ref(), env.clone(), QueryMsg::NextDigest { msgs: msgs.clone() }).unwrap()).unwrap();
        let at0: Binary =
            from_json(query(deps.as_ref(), env.clone(), QueryMsg::DigestAt { idx: 0, msgs: msgs.clone() }).unwrap()).unwrap();
        let at5: Binary =
            from_json(query(deps.as_ref(), env.clone(), QueryMsg::DigestAt { idx: 5, msgs: msgs.clone() }).unwrap()).unwrap();
        assert_eq!(next, at0, "next_digest is digest_at(next_idx)");
        assert_ne!(at0, at5, "the leaf index is part of the digest");
        assert_eq!(at5.len(), 32);
    }

    #[test]
    fn needs_top_layer_at_reports_uncached_subtrees() {
        let (mut deps, env) = setup();
        let q = |deps: Deps, m: QueryMsg| -> bool { from_json(query(deps, env.clone(), m).unwrap()).unwrap() };
        assert!(q(deps.as_ref(), QueryMsg::NeedsTopLayer {}));
        assert!(q(deps.as_ref(), QueryMsg::NeedsTopLayerAt { idx: 5 }));
        assert!(q(deps.as_ref(), QueryMsg::NeedsTopLayerAt { idx: 1024 }));

        // Register subtree 0 directly in storage.
        CACHE.save(&mut deps.storage, (0, 0), &Binary::from(vec![0x33u8; 32])).unwrap();
        assert!(!q(deps.as_ref(), QueryMsg::NeedsTopLayer {}));
        assert!(!q(deps.as_ref(), QueryMsg::NeedsTopLayerAt { idx: 5 }));
        assert!(!q(deps.as_ref(), QueryMsg::NeedsTopLayerAt { idx: 1023 }));
        assert!(q(deps.as_ref(), QueryMsg::NeedsTopLayerAt { idx: 1024 }), "subtree 1 is still uncached");
    }

    #[test]
    fn index_below_next_idx_is_rejected_before_hashing() {
        let (mut deps, env) = setup();
        set_next_idx(&mut deps, 6);
        let info = message_info(&deps.api.addr_make("anyone"), &[]);

        // Deliberately malformed layers: the index check must fire first.
        let bad_layer = LayerSigMsg { wots: vec![], auth: vec![] };
        for idx in [0u64, 1, 5] {
            let err = execute(
                deps.as_mut(),
                env.clone(),
                info.clone(),
                ExecuteMsg::Execute { idx, l0: bad_layer.clone(), l1: None, msgs: sample_msgs() },
            )
            .unwrap_err();
            assert!(matches!(err, ContractError::IndexUsed), "idx {idx}: {err}");
        }
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Execute { idx: 1 << 20, l0: bad_layer.clone(), l1: None, msgs: sample_msgs() },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Exhausted), "{err}");

        // idx == next_idx passes the index check and fails on the layer shape.
        let err = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Execute { idx: 6, l0: bad_layer, l1: None, msgs: sample_msgs() },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::BadLength { .. }), "{err}");
        assert_eq!(STATE.load(&deps.storage).unwrap().next_idx, 6, "state untouched on error");
    }

    #[test]
    fn jump_to_uncached_subtree_without_top_layer_is_rejected() {
        let (mut deps, env) = setup();
        let info = message_info(&deps.api.addr_make("anyone"), &[]);
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Execute { idx: 1024, l0: zero_layer(H), l1: None, msgs: sample_msgs() },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::MissingTopLayer), "{err}");
        assert_eq!(STATE.load(&deps.storage).unwrap().next_idx, 0);
    }
}
