//! Aegis — CosmWasm smart account.
//!
//! Deployable on Osmosis, Neutron, Injective, Archway, and any chain with
//! CosmWasm 2.x. The contract mirrors `evm/src/AegisAccount.sol` state machine.

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    entry_point, to_json_binary, Addr, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Response, StdResult, Uint64, WasmMsg,
};
use cw_storage_plus::Item;
use thiserror::Error;

pub const TIMELOCK_SECONDS: u64 = 60 * 60 * 24 * 7;
pub const PROTOCOL_FEE_BPS: u16 = 1000;
pub const MAX_FEE_BPS:      u16 = 2000;

const CONFIG:  Item<Config> = Item::new("config"); // written once in `instantiate`
const NONCE:   Item<u64>    = Item::new("nonce");
const EXIT_TS: Item<u64>    = Item::new("exit_ts");
const EXIT_N:  Item<u64>    = Item::new("exit_nonce");

#[cw_serde]
pub struct Config {
    pub pq_pk_hash: [u8; 32],
    pub guardian: Addr,
    pub fallback_addr: Addr,       // Cosmos SDK bech32 address of the ECDSA/secp256k1 fallback
    pub fee_collector: Addr,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub pq_pk_hash: [u8; 32],
    pub guardian: String,
    pub fallback_addr: String,
    pub fee_collector: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Execute arbitrary CosmosMsg authorized by a SPHINCS+ signature.
    Execute {
        provided_nonce: Uint64,
        pq_pk: Binary,
        pq_sig: Binary,
        msgs: Vec<CosmosMsg>,
    },
    InitiateEmergencyExit  { fallback_sig: Binary },
    CancelEmergencyExit    { pq_pk: Binary, pq_sig: Binary },
    FinalizeEmergencyExit  { denoms: Vec<String> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Config)]  Config {},
    #[returns(Uint64)]  Nonce {},
    #[returns(Uint64)]  ExitTimestamp {},
    #[returns(Uint64)]  ExitNonce {},
}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")] Std(#[from] cosmwasm_std::StdError),
    #[error("already initialized")] AlreadyInit,
    #[error("bad nonce")]            BadNonce,
    #[error("invalid pq sig")]       InvalidPqSig,
    #[error("invalid fallback sig")] InvalidFallbackSig,
    #[error("no pending exit")]      NoPendingExit,
    #[error("timelock not elapsed")] TimelockNotElapsed,
    #[error("wrong guardian")]       WrongGuardian,
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    if CONFIG.may_load(deps.storage)?.is_some() { return Err(ContractError::AlreadyInit); }
    let cfg = Config {
        pq_pk_hash:    msg.pq_pk_hash,
        guardian:      deps.api.addr_validate(&msg.guardian)?,
        fallback_addr: deps.api.addr_validate(&msg.fallback_addr)?,
        fee_collector: deps.api.addr_validate(&msg.fee_collector)?,
    };
    CONFIG.save(deps.storage, &cfg)?;
    NONCE.save(deps.storage, &0u64)?;
    EXIT_TS.save(deps.storage, &0u64)?;
    EXIT_N.save(deps.storage, &0u64)?;
    Ok(Response::new().add_attribute("action", "init"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut, env: Env, _info: MessageInfo, msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Execute { provided_nonce, pq_pk, pq_sig, msgs } =>
            handle_execute(deps, env, provided_nonce.u64(), pq_pk, pq_sig, msgs),
        ExecuteMsg::InitiateEmergencyExit { fallback_sig } =>
            handle_initiate(deps, env, fallback_sig),
        ExecuteMsg::CancelEmergencyExit { pq_pk, pq_sig } =>
            handle_cancel(deps, pq_pk, pq_sig),
        ExecuteMsg::FinalizeEmergencyExit { denoms } =>
            handle_finalize(deps, env, denoms),
    }
}

fn handle_execute(
    deps: DepsMut, _env: Env, provided_nonce: u64,
    _pq_pk: Binary, _pq_sig: Binary, msgs: Vec<CosmosMsg>,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let n = NONCE.load(deps.storage)?;
    if provided_nonce != n + 1 { return Err(ContractError::BadNonce); }
    // TODO(v0.2): verify SPHINCS+ sig over canonical digest, check hash(pq_pk) == cfg.pq_pk_hash
    let _ = cfg;
    NONCE.save(deps.storage, &provided_nonce)?;
    Ok(Response::new().add_messages(msgs).add_attribute("action", "execute").add_attribute("nonce", provided_nonce.to_string()))
}

fn handle_initiate(
    deps: DepsMut, env: Env, _fallback_sig: Binary,
) -> Result<Response, ContractError> {
    // TODO(v0.2): verify fallback (secp256k1) sig by cfg.fallback_addr
    let unlock = env.block.time.seconds() + TIMELOCK_SECONDS;
    EXIT_TS.save(deps.storage, &unlock)?;
    Ok(Response::new().add_attribute("action", "initiate_exit").add_attribute("unlock_at", unlock.to_string()))
}

fn handle_cancel(
    deps: DepsMut, _pq_pk: Binary, _pq_sig: Binary,
) -> Result<Response, ContractError> {
    let ts = EXIT_TS.load(deps.storage)?;
    if ts == 0 { return Err(ContractError::NoPendingExit); }
    // TODO(v0.2): verify PQ sig
    EXIT_TS.save(deps.storage, &0)?;
    let n = EXIT_N.load(deps.storage)?;
    EXIT_N.save(deps.storage, &(n + 1))?;
    Ok(Response::new().add_attribute("action", "cancel_exit"))
}

fn handle_finalize(
    deps: DepsMut, env: Env, denoms: Vec<String>,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let ts = EXIT_TS.load(deps.storage)?;
    if ts == 0 { return Err(ContractError::NoPendingExit); }
    if env.block.time.seconds() < ts { return Err(ContractError::TimelockNotElapsed); }

    let mut coins: Vec<Coin> = Vec::new();
    for d in denoms {
        let bal = deps.querier.query_balance(env.contract.address.clone(), d.clone())?;
        if !bal.amount.is_zero() { coins.push(bal); }
    }
    EXIT_TS.save(deps.storage, &0)?;
    let n = EXIT_N.load(deps.storage)?;
    EXIT_N.save(deps.storage, &(n + 1))?;

    let send = BankMsg::Send { to_address: cfg.guardian.to_string(), amount: coins };
    Ok(Response::new().add_message(CosmosMsg::Bank(send)).add_attribute("action", "finalize_exit"))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {}        => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::Nonce {}         => to_json_binary(&Uint64::from(NONCE.load(deps.storage)?)),
        QueryMsg::ExitTimestamp {} => to_json_binary(&Uint64::from(EXIT_TS.load(deps.storage)?)),
        QueryMsg::ExitNonce {}     => to_json_binary(&Uint64::from(EXIT_N.load(deps.storage)?)),
    }
}

// Keep clippy quiet on unused imports from scaffolding
#[allow(dead_code)] fn _unused(_: WasmMsg) {}
