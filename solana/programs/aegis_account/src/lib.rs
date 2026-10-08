//! Aegis CCHS-S-20 post-quantum smart account for Solana.
//!
//! Authorization is a WOTS+ (SHA-256, w = 16, 67 chains) signature under a
//! two-layer hypertree of height 10 + 10. The top-layer proof for each bottom
//! subtree is verified once and cached in a `SubtreeCache` PDA keyed by
//! `(account, epoch, tree_idx)`; the next 1023 signatures in that subtree carry
//! only the bottom layer. The verification algorithm lives in `cchs-core` and
//! is byte-exact with `evm/src/AegisCCHS.sol`; this program only adds the
//! Solana-specific digest, storage layout and CPI dispatch.
//!
//! Accounts:
//!   * `CchsAccount` PDA  — seeds `["cchs", initial_root]`; holds the state.
//!   * `SubtreeCache` PDA — seeds `["cache", account, epoch LE, tree_idx LE]`;
//!                           created on first use of a bottom subtree.
//!   * vault PDA          — seeds `["vault", account]`; a data-less system
//!                           account that holds SOL / token authority and
//!                           co-signs every CPI so the account can pay.
//!
//! Message digest (32 bytes, signed by the client):
//!   sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account(32) ‖ nonce u64 BE ‖ idx u64 BE
//!          ‖ sha256(target_program(32) ‖ ix_data))
//! Recovery digest:
//!   sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account(32) ‖ rec_nonce u64 BE
//!          ‖ new_root ‖ new_rec_root)
//!
//! Spec: ../../../../CCHS.spec.md

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use cchs_core::{CchsError, CchsState, LayerSig, Sha256, H, LEN, REC_H};

// Placeholder program id (valid 32-byte key); replace with the deployed
// keypair's public key before deployment (`anchor keys sync`).
declare_id!("4Zto6EPTKp6p8VwMRCUKg28BhNjXDcpHMvEisRherJsr");

pub const ACCOUNT_SEED: &[u8] = b"cchs";
pub const CACHE_SEED: &[u8] = b"cache";
pub const VAULT_SEED: &[u8] = b"vault";

/// Domain tag bound into every execute digest.
pub const DOMAIN_EXECUTE: &[u8] = b"AEGIS_CCHS_V1";
/// Domain tag bound into every recovery digest.
pub const DOMAIN_RECOVER: &[u8] = b"AEGIS_CCHS_RECOVER_V1";
/// Chain identifier bound into every digest (replaces the EVM chain id).
pub const CHAIN_TAG: &[u8] = b"solana";

// ------------------------------------------------------------------- hash

/// SHA-256 through the `sol_sha256` syscall. Input is accumulated in a heap
/// buffer (largest input is the 2176-byte leaf compression) and hashed in a
/// single syscall per digest, which is the cheapest path in compute units.
pub struct SolSha256 {
    buf: Vec<u8>,
}

impl Default for SolSha256 {
    fn default() -> Self {
        SolSha256 { buf: Vec::with_capacity(32 + 32 * LEN) }
    }
}

impl Sha256 for SolSha256 {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn finish(&mut self) -> [u8; 32] {
        let out = hashv(&[self.buf.as_slice()]).to_bytes();
        self.buf.clear();
        out
    }
}

// ---------------------------------------------------------------- program

#[program]
pub mod aegis_account {
    use super::*;

    /// Create the account PDA with its top-layer root and recovery root.
    pub fn initialize(ctx: Context<Initialize>, root: [u8; 32], rec_root: [u8; 32]) -> Result<()> {
        let state = CchsState::new(root, rec_root).map_err(map_err)?;
        let account_key = ctx.accounts.account.key();
        let (_, vault_bump) =
            Pubkey::find_program_address(&[VAULT_SEED, account_key.as_ref()], ctx.program_id);

        let acc = &mut ctx.accounts.account;
        acc.seed = root;
        store_state(acc, &state);
        acc.bump = ctx.bumps.account;
        acc.vault_bump = vault_bump;
        emit!(Initialized { account: account_key, root, rec_root });
        Ok(())
    }

    /// Execute `target_program(ix_data)` with the accounts passed as
    /// `remaining_accounts`, authorized by a CCHS signature on the digest of
    /// `(account, nonce, next_idx, target_program, ix_data)`.
    ///
    /// * `l0_wots` / `l0_auth` — 67 chain values and 10 siblings for leaf `next_idx`.
    /// * `has_l1` — true on the first use of a bottom subtree (cache PDA is empty).
    /// * `l1_wots` / `l1_auth` — top-layer signature on the bottom root; ignored
    ///   when `has_l1` is false (pass empty vectors).
    ///
    /// The account PDA and the vault PDA both sign the CPI.
    pub fn execute<'info>(
        ctx: Context<'_, '_, 'info, 'info, Execute<'info>>,
        l0_wots: Vec<[u8; 32]>,
        l0_auth: Vec<[u8; 32]>,
        has_l1: bool,
        l1_wots: Vec<[u8; 32]>,
        l1_auth: Vec<[u8; 32]>,
        target_program: Pubkey,
        ix_data: Vec<u8>,
    ) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let cached = cached_root(&ctx.accounts.cache);

        let mut h = SolSha256::default();
        let acc = &mut ctx.accounts.account;
        let idx = acc.next_idx;
        let msg = execute_digest(&mut h, &account_key, acc.nonce, idx, &target_program, &ix_data);

        let l0 = layer(&l0_wots, &l0_auth)?;
        let l1 = if has_l1 { Some(layer(&l1_wots, &l1_auth)?) } else { None };

        let mut state = load_state(acc);
        let outcome = state.execute_verify(&mut h, &msg, l0, l1, cached).map_err(map_err)?;
        store_state(acc, &state);

        let seed = acc.seed;
        let bump = acc.bump;
        let vault_bump = acc.vault_bump;

        if outcome.cache_write {
            ctx.accounts.cache.root = outcome.subtree_root;
            emit!(SubtreeCached {
                account: account_key,
                epoch: state.epoch,
                tree_idx: outcome.tree_idx,
                subtree_root: outcome.subtree_root,
            });
        }

        // --- effects done; interaction ---
        let (vault_key, _) =
            Pubkey::find_program_address(&[VAULT_SEED, account_key.as_ref()], ctx.program_id);
        let metas: Vec<AccountMeta> = ctx
            .remaining_accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: *a.key,
                is_signer: a.is_signer || *a.key == account_key || *a.key == vault_key,
                is_writable: a.is_writable,
            })
            .collect();
        let ix = Instruction { program_id: target_program, accounts: metas, data: ix_data };

        let bump_bytes = [bump];
        let vault_bump_bytes = [vault_bump];
        let account_seeds: &[&[u8]] = &[ACCOUNT_SEED, seed.as_ref(), &bump_bytes];
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, account_key.as_ref(), &vault_bump_bytes];
        invoke_signed(&ix, ctx.remaining_accounts, &[account_seeds, vault_seeds])?;

        emit!(Executed { account: account_key, idx, target_program });
        Ok(())
    }

    /// Rotate `root` and `rec_root`, authorized by the recovery tree
    /// (layer 0xFF, height 8, leaf `rec_nonce`). Resets `next_idx` and bumps
    /// `epoch`, which invalidates every existing `SubtreeCache` PDA.
    pub fn recover(
        ctx: Context<Recover>,
        new_root: [u8; 32],
        new_rec_root: [u8; 32],
        wots: Vec<[u8; 32]>,
        auth: Vec<[u8; 32]>,
    ) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let acc = &mut ctx.accounts.account;

        let wots: &[[u8; 32]; LEN] =
            wots.as_slice().try_into().map_err(|_| error!(AegisError::BadLength))?;
        require!(auth.len() == REC_H, AegisError::BadLength);

        let mut h = SolSha256::default();
        let msg = recover_digest(&mut h, &account_key, acc.rec_nonce, &new_root, &new_rec_root);

        let mut state = load_state(acc);
        let epoch = state
            .recover_verify(&mut h, &msg, new_root, new_rec_root, wots, &auth)
            .map_err(map_err)?;
        store_state(acc, &state);

        emit!(Recovered { account: account_key, epoch, new_root, new_rec_root });
        Ok(())
    }
}

// ---------------------------------------------------------------- digests

/// `sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account ‖ nonce BE ‖ idx BE ‖ sha256(target_program ‖ ix_data))`
pub fn execute_digest(
    h: &mut SolSha256,
    account: &Pubkey,
    nonce: u64,
    idx: u64,
    target_program: &Pubkey,
    ix_data: &[u8],
) -> [u8; 32] {
    h.update(target_program.as_ref());
    h.update(ix_data);
    let inner = h.finish();

    h.update(DOMAIN_EXECUTE);
    h.update(CHAIN_TAG);
    h.update(account.as_ref());
    h.update(&nonce.to_be_bytes());
    h.update(&idx.to_be_bytes());
    h.update(&inner);
    h.finish()
}

/// `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account ‖ rec_nonce BE ‖ new_root ‖ new_rec_root)`
pub fn recover_digest(
    h: &mut SolSha256,
    account: &Pubkey,
    rec_nonce: u64,
    new_root: &[u8; 32],
    new_rec_root: &[u8; 32],
) -> [u8; 32] {
    h.update(DOMAIN_RECOVER);
    h.update(CHAIN_TAG);
    h.update(account.as_ref());
    h.update(&rec_nonce.to_be_bytes());
    h.update(new_root);
    h.update(new_rec_root);
    h.finish()
}

// ---------------------------------------------------------------- helpers

fn layer<'a>(wots: &'a [[u8; 32]], auth: &'a [[u8; 32]]) -> Result<LayerSig<'a>> {
    let wots: &'a [[u8; 32]; LEN] = wots.try_into().map_err(|_| error!(AegisError::BadLength))?;
    require!(auth.len() == H, AegisError::BadLength);
    Ok(LayerSig { wots, auth })
}

fn cached_root(cache: &SubtreeCache) -> Option<[u8; 32]> {
    if cache.root == [0u8; 32] {
        None
    } else {
        Some(cache.root)
    }
}

fn load_state(a: &CchsAccount) -> CchsState {
    CchsState {
        root: a.root,
        rec_root: a.rec_root,
        epoch: a.epoch,
        next_idx: a.next_idx,
        nonce: a.nonce,
        rec_nonce: a.rec_nonce,
    }
}

fn store_state(a: &mut CchsAccount, s: &CchsState) {
    a.root = s.root;
    a.rec_root = s.rec_root;
    a.epoch = s.epoch;
    a.next_idx = s.next_idx;
    a.nonce = s.nonce;
    a.rec_nonce = s.rec_nonce;
}

fn map_err(e: CchsError) -> anchor_lang::error::Error {
    match e {
        CchsError::Exhausted => error!(AegisError::Exhausted),
        CchsError::MissingTopLayer => error!(AegisError::MissingTopLayer),
        CchsError::BadSubtreeRoot => error!(AegisError::BadSubtreeRoot),
        CchsError::BadTopRoot => error!(AegisError::BadTopRoot),
        CchsError::BadRecovery => error!(AegisError::BadRecovery),
        CchsError::ZeroRoot => error!(AegisError::ZeroRoot),
        CchsError::BadLength => error!(AegisError::BadLength),
    }
}

// --------------------------------------------------------------- accounts

#[derive(Accounts)]
#[instruction(root: [u8; 32], rec_root: [u8; 32])]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [ACCOUNT_SEED, root.as_ref()],
        bump,
        space = 8 + CchsAccount::INIT_SPACE,
    )]
    pub account: Account<'info, CchsAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(
        mut,
        seeds = [ACCOUNT_SEED, account.seed.as_ref()],
        bump = account.bump,
    )]
    pub account: Account<'info, CchsAccount>,
    /// Cache slot for the bottom subtree of `account.next_idx` in the current
    /// epoch. Created (zeroed) on first use; a zero root means "not cached".
    #[account(
        init_if_needed,
        payer = payer,
        seeds = [
            CACHE_SEED,
            account.key().as_ref(),
            &account.epoch.to_le_bytes(),
            &(account.next_idx >> 10).to_le_bytes(),
        ],
        bump,
        space = 8 + SubtreeCache::INIT_SPACE,
    )]
    pub cache: Account<'info, SubtreeCache>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
    // remaining_accounts: every account of the CPI, including the target
    // program itself and, when needed, `account` and/or the vault PDA.
}

#[derive(Accounts)]
pub struct Recover<'info> {
    #[account(
        mut,
        seeds = [ACCOUNT_SEED, account.seed.as_ref()],
        bump = account.bump,
    )]
    pub account: Account<'info, CchsAccount>,
}

// ------------------------------------------------------------------ state

#[account]
#[derive(InitSpace)]
pub struct CchsAccount {
    /// Immutable PDA seed (the root given at initialization).
    pub seed: [u8; 32],
    /// Top-layer tree root. Rotatable only via `recover`.
    pub root: [u8; 32],
    /// Recovery tree root (single layer, height 8).
    pub rec_root: [u8; 32],
    /// Increments on every recovery; namespaces the cache PDAs.
    pub epoch: u64,
    /// Next unused leaf index in [0, 2^20).
    pub next_idx: u64,
    /// Transaction nonce bound into every message digest.
    pub nonce: u64,
    /// Next unused recovery leaf in [0, 256).
    pub rec_nonce: u64,
    pub bump: u8,
    pub vault_bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct SubtreeCache {
    /// Verified bottom subtree root, or all zero when not yet cached.
    pub root: [u8; 32],
}

// ----------------------------------------------------------------- events

#[event]
pub struct Initialized {
    pub account: Pubkey,
    pub root: [u8; 32],
    pub rec_root: [u8; 32],
}

#[event]
pub struct Executed {
    pub account: Pubkey,
    pub idx: u64,
    pub target_program: Pubkey,
}

#[event]
pub struct SubtreeCached {
    pub account: Pubkey,
    pub epoch: u64,
    pub tree_idx: u64,
    pub subtree_root: [u8; 32],
}

#[event]
pub struct Recovered {
    pub account: Pubkey,
    pub epoch: u64,
    pub new_root: [u8; 32],
    pub new_rec_root: [u8; 32],
}

// ----------------------------------------------------------------- errors

#[error_code]
pub enum AegisError {
    #[msg("signature capacity exhausted")]
    Exhausted,
    #[msg("subtree not cached and no top-layer proof supplied")]
    MissingTopLayer,
    #[msg("bottom root does not match cached subtree root")]
    BadSubtreeRoot,
    #[msg("top-layer path does not reach root")]
    BadTopRoot,
    #[msg("recovery path does not reach recovery root")]
    BadRecovery,
    #[msg("zero root")]
    ZeroRoot,
    #[msg("wrong number of chain values or auth siblings")]
    BadLength,
}
