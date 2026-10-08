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
//! Message digest (32 bytes, signed by the client):
//!   sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ nonce u64 BE
//!          ‖ idx u64 BE ‖ sha256(to_json_binary(msgs)))
//! Recovery digest:
//!   sha256("AEGIS_CCHS_RECOVER_V1" ‖ "cosmwasm" ‖ contract_address_utf8
//!          ‖ rec_nonce u64 BE ‖ new_root ‖ new_rec_root)
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

use cchs_core::{CchsError, CchsState, LayerSig, Sha256 as CchsHash, H, LEN, REC_H};

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
    /// Increments on every recovery; namespaces the cache.
    pub epoch: u64,
    /// Next unused leaf index in [0, 2^20).
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
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Dispatch `msgs` from the contract, authorized by a CCHS signature on
    /// the digest of `(contract, nonce, next_idx, msgs)`. `l1` is required on
    /// the first use of a bottom subtree (see `QueryMsg::NeedsTopLayer`).
    Execute {
        l0: LayerSigMsg,
        l1: Option<LayerSigMsg>,
        msgs: Vec<CosmosMsg>,
    },
    /// Rotate both roots, authorized by the recovery tree at leaf `rec_nonce`.
    Recover {
        new_root: Binary,
        new_rec_root: Binary,
        wots: Vec<Binary>,
        auth: Vec<Binary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(State)]
    State {},
    /// Digest the client must sign for the next `Execute` of `msgs`.
    #[returns(Binary)]
    NextDigest { msgs: Vec<CosmosMsg> },
    /// Digest the client must sign for the next `Recover`.
    #[returns(Binary)]
    NextRecoveryDigest { new_root: Binary, new_rec_root: Binary },
    /// Whether the next `Execute` must include the top layer.
    #[returns(bool)]
    NeedsTopLayer {},
}

// ----------------------------------------------------------------- errors

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] cosmwasm_std::StdError),
    #[error("signature capacity exhausted")]
    Exhausted,
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
    let state = CchsState::new(root, rec_root)?;
    STATE.save(deps.storage, &to_stored(&state))?;
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("root", msg.root.to_base64())
        .add_attribute("rec_root", msg.rec_root.to_base64()))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Execute { l0, l1, msgs } => exec_execute(deps, env, l0, l1, msgs),
        ExecuteMsg::Recover { new_root, new_rec_root, wots, auth } => {
            exec_recover(deps, env, new_root, new_rec_root, wots, auth)
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
        QueryMsg::NextRecoveryDigest { new_root, new_rec_root } => {
            let st = STATE.load(deps.storage)?;
            let d = recover_digest(&env, st.rec_nonce, new_root.as_slice(), new_rec_root.as_slice());
            to_json_binary(&Binary::from(d.to_vec()))
        }
        QueryMsg::NeedsTopLayer {} => {
            let st = STATE.load(deps.storage)?;
            let cached = CACHE.may_load(deps.storage, (st.epoch, st.next_idx >> H))?;
            let cached = cached.and_then(|b| b32(&b).ok());
            to_json_binary(&CchsState::needs_top_layer(cached))
        }
    }
}

// --------------------------------------------------------------- handlers

fn exec_execute(
    deps: DepsMut,
    env: Env,
    l0: LayerSigMsg,
    l1: Option<LayerSigMsg>,
    msgs: Vec<CosmosMsg>,
) -> Result<Response, ContractError> {
    let stored = STATE.load(deps.storage)?;
    let mut state = from_stored(&stored)?;
    let idx = state.next_idx;
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
    let outcome = state.execute_verify(&mut h, &digest, l0.sig(), l1_sig, cached)?;

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
    wots: Vec<Binary>,
    auth: Vec<Binary>,
) -> Result<Response, ContractError> {
    let stored = STATE.load(deps.storage)?;
    let mut state = from_stored(&stored)?;

    let new_root_b = b32(&new_root)?;
    let new_rec_root_b = b32(&new_rec_root)?;
    let layer = parse_layer(&LayerSigMsg { wots, auth }, REC_H)?;

    let digest = recover_digest(&env, state.rec_nonce, &new_root_b, &new_rec_root_b);

    let mut h = Hasher::default();
    let epoch =
        state.recover_verify(&mut h, &digest, new_root_b, new_rec_root_b, &layer.wots, &layer.auth)?;
    STATE.save(deps.storage, &to_stored(&state))?;

    Ok(Response::new()
        .add_attribute("action", "recover")
        .add_attribute("epoch", epoch.to_string())
        .add_attribute("root", new_root.to_base64())
        .add_attribute("rec_root", new_rec_root.to_base64()))
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

/// `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "cosmwasm" ‖ contract_address ‖ rec_nonce BE ‖ new_root ‖ new_rec_root)`
pub fn recover_digest(env: &Env, rec_nonce: u64, new_root: &[u8], new_rec_root: &[u8]) -> [u8; 32] {
    let mut h = Hasher::default();
    CchsHash::update(&mut h, DOMAIN_RECOVER);
    CchsHash::update(&mut h, CHAIN_TAG);
    CchsHash::update(&mut h, env.contract.address.as_bytes());
    CchsHash::update(&mut h, &rec_nonce.to_be_bytes());
    CchsHash::update(&mut h, new_root);
    CchsHash::update(&mut h, new_rec_root);
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

fn to_stored(s: &CchsState) -> State {
    State {
        root: Binary::from(s.root.to_vec()),
        rec_root: Binary::from(s.rec_root.to_vec()),
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
        epoch: s.epoch,
        next_idx: s.next_idx,
        nonce: s.nonce,
        rec_nonce: s.rec_nonce,
    })
}
