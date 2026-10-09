//! Aegis CCHS-C-20 post-quantum smart account for Solana.
//!
//! Authorization is a WOTS+ signature (SHA-256 truncated to 24 bytes,
//! w = 256, 26 chains) under a two-layer hypertree of height 10 + 10. One
//! layer is 26 × 24 + 10 × 24 = 864 bytes, so the hot path fits a single
//! 1 232-byte Solana packet:
//!
//! * `cache_subtree` verifies the top-layer proof for one bottom subtree root
//!   `r0` and stores it in a `SubtreeCache` PDA keyed by
//!   `(account, epoch, tree_idx)`. Done once per 1 024 signatures, in its own
//!   transaction, by anyone (the proof is self-authenticating).
//! * `execute` carries only the bottom layer, recomputes `r0` from it and
//!   requires the cache PDA to hold exactly that value. No top layer is ever
//!   accepted here, which is what keeps the instruction inside one packet.
//!
//! The verification algorithm lives in `cchs_core::compact` and is byte-exact
//! with `wallet/src/aegis/cchsCompact.ts`; this program only adds the Solana
//! digest, storage layout and CPI dispatch.
//!
//! Accounts:
//!   * `CchsAccount` PDA  — seeds `["cchs", initial_root(24)]`; holds the state.
//!   * `SubtreeCache` PDA — seeds `["cache", account, epoch LE, tree_idx LE]`;
//!                           created by `cache_subtree`, read by `execute`.
//!   * vault PDA          — seeds `["vault", account]`; a data-less system
//!                           account that holds SOL / token authority and
//!                           co-signs every CPI so the account can pay.
//!
//! Message digest (24 bytes, signed by the client):
//!   sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account(32) ‖ nonce u64 BE ‖ idx u64 BE
//!          ‖ sha256(target_program(32) ‖ ix_data))[0..24)
//! Recovery digest:
//!   sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account(32) ‖ rec_nonce u64 BE
//!          ‖ new_root(24) ‖ new_rec_root(24))[0..24)
//!
//! Spec: ../../../../CCHS.spec.md

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use cchs_core::compact::{verify_top_layer, CchsState, Hash, LayerSig, LEN, N, ZERO};
use cchs_core::{CchsError, Sha256};

// Fixed instruction-argument shapes. Spelled out as literals so the Anchor
// IDL builder sees plain array types; the compiler checks them against
// `cchs_core::compact::{LEN, H, REC_H}` wherever they are passed to the core.
const _: () = assert!(LEN == 26);
const _: () = assert!(cchs_core::compact::H == 10);
const _: () = assert!(cchs_core::compact::REC_H == 8);
const _: () = assert!(N == 24);

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

/// Largest hash input: the leaf compression `ADRS(32) ‖ 26 × 24`.
pub const MAX_HASH_INPUT: usize = 32 + LEN * N;

// ------------------------------------------------------------------- hash

/// SHA-256 through the `sol_sha256` syscall. Input is accumulated in a heap
/// buffer (largest input is the 656-byte leaf compression) and hashed in a
/// single syscall per digest. Truncation to 24 bytes is done by `cchs_core`.
pub struct SolSha256 {
    buf: Vec<u8>,
}

impl Default for SolSha256 {
    fn default() -> Self {
        SolSha256 { buf: Vec::with_capacity(MAX_HASH_INPUT) }
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

    /// Create the account PDA with its top-layer root and recovery root
    /// (24 bytes each). Instruction data: 8 + 24 + 24 = 56 bytes.
    pub fn create(ctx: Context<Create>, root: [u8; 24], rec_root: [u8; 24]) -> Result<()> {
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

    /// Register bottom subtree `tree_idx` with root `r0`: verifies the
    /// top-layer WOTS+ signature on `r0` at top leaf `tree_idx` against
    /// `account.root` and writes `r0` into the cache PDA for the current
    /// epoch. Instruction data: 8 + 8 + 624 + 240 + 24 = 904 bytes.
    ///
    /// Anyone may call this; the proof authenticates itself. A slot that
    /// already holds `r0` is accepted (idempotent); a slot holding a
    /// different non-zero value is rejected.
    pub fn cache_subtree(
        ctx: Context<CacheSubtree>,
        tree_idx: u64,
        l1_wots: [[u8; 24]; 26],
        l1_auth: [[u8; 24]; 10],
        r0: [u8; 24],
    ) -> Result<()> {
        require!(r0 != ZERO, AegisError::ZeroRoot);
        let account_key = ctx.accounts.account.key();
        let acc = &ctx.accounts.account;

        let mut h = SolSha256::default();
        verify_top_layer(&mut h, &acc.root, tree_idx, &r0, LayerSig { wots: &l1_wots, auth: &l1_auth })
            .map_err(map_err)?;

        let cache = &mut ctx.accounts.cache;
        require!(cache.root == ZERO || cache.root == r0, AegisError::CacheConflict);
        cache.root = r0;

        emit!(SubtreeCached { account: account_key, epoch: acc.epoch, tree_idx, subtree_root: r0 });
        Ok(())
    }

    /// Execute `target_program(ix_data)` with the accounts passed as
    /// `remaining_accounts`, authorized by a bottom-layer CCHS signature on
    /// the digest of `(account, nonce, next_idx, target_program, ix_data)`.
    /// The bottom subtree root recomputed from the signature must equal the
    /// value stored by `cache_subtree`. Instruction data:
    /// 8 + 624 + 240 + 4 + ix_data.len() bytes.
    ///
    /// The account PDA and the vault PDA both sign the CPI.
    pub fn execute<'info>(
        ctx: Context<'_, '_, 'info, 'info, Execute<'info>>,
        l0_wots: [[u8; 24]; 26],
        l0_auth: [[u8; 24]; 10],
        ix_data: Vec<u8>,
    ) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let target_program = ctx.accounts.target_program.key();
        require!(ctx.accounts.target_program.executable, AegisError::TargetNotExecutable);

        let cached = ctx.accounts.cache.root;
        require!(cached != ZERO, AegisError::MissingTopLayer);

        let mut h = SolSha256::default();
        let acc = &mut ctx.accounts.account;
        let idx = acc.next_idx;
        let msg = execute_digest(&mut h, &account_key, acc.nonce, idx, &target_program, &ix_data);

        let mut state = load_state(acc);
        let outcome = state
            .execute_cached(&mut h, &msg, LayerSig { wots: &l0_wots, auth: &l0_auth }, cached)
            .map_err(map_err)?;
        store_state(acc, &state);

        let seed = acc.seed;
        let bump = acc.bump;
        let vault_bump = acc.vault_bump;

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

        let mut infos: Vec<AccountInfo<'info>> = ctx.remaining_accounts.to_vec();
        infos.push(ctx.accounts.target_program.to_account_info());

        let bump_bytes = [bump];
        let vault_bump_bytes = [vault_bump];
        let account_seeds: &[&[u8]] = &[ACCOUNT_SEED, seed.as_ref(), &bump_bytes];
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, account_key.as_ref(), &vault_bump_bytes];
        invoke_signed(&ix, &infos, &[account_seeds, vault_seeds])?;

        emit!(Executed { account: account_key, idx: outcome.idx, target_program });
        Ok(())
    }

    /// Rotate `root` and `rec_root`, authorized by the recovery tree
    /// (layer 0xFF, height 8, leaf `rec_nonce`). Resets `next_idx` and bumps
    /// `epoch`, which invalidates every existing `SubtreeCache` PDA.
    /// Instruction data: 8 + 24 + 24 + 624 + 192 = 872 bytes.
    pub fn recover(
        ctx: Context<Recover>,
        new_root: [u8; 24],
        new_rec_root: [u8; 24],
        wots: [[u8; 24]; 26],
        auth: [[u8; 24]; 8],
    ) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let acc = &mut ctx.accounts.account;

        let mut h = SolSha256::default();
        let msg = recover_digest(&mut h, &account_key, acc.rec_nonce, &new_root, &new_rec_root);

        let mut state = load_state(acc);
        let epoch = state
            .recover_verify(&mut h, &msg, new_root, new_rec_root, &wots, &auth)
            .map_err(map_err)?;
        store_state(acc, &state);

        emit!(Recovered { account: account_key, epoch, new_root, new_rec_root });
        Ok(())
    }
}

// ---------------------------------------------------------------- digests

fn truncate(d: [u8; 32]) -> Hash {
    let mut out = [0u8; N];
    out.copy_from_slice(&d[..N]);
    out
}

/// `sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account ‖ nonce BE ‖ idx BE ‖ sha256(target_program ‖ ix_data))[0..24)`
pub fn execute_digest(
    h: &mut SolSha256,
    account: &Pubkey,
    nonce: u64,
    idx: u64,
    target_program: &Pubkey,
    ix_data: &[u8],
) -> Hash {
    h.update(target_program.as_ref());
    h.update(ix_data);
    let inner = h.finish();

    h.update(DOMAIN_EXECUTE);
    h.update(CHAIN_TAG);
    h.update(account.as_ref());
    h.update(&nonce.to_be_bytes());
    h.update(&idx.to_be_bytes());
    h.update(&inner);
    truncate(h.finish())
}

/// `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account ‖ rec_nonce BE ‖ new_root ‖ new_rec_root)[0..24)`
pub fn recover_digest(
    h: &mut SolSha256,
    account: &Pubkey,
    rec_nonce: u64,
    new_root: &Hash,
    new_rec_root: &Hash,
) -> Hash {
    h.update(DOMAIN_RECOVER);
    h.update(CHAIN_TAG);
    h.update(account.as_ref());
    h.update(&rec_nonce.to_be_bytes());
    h.update(new_root);
    h.update(new_rec_root);
    truncate(h.finish())
}

// ---------------------------------------------------------------- helpers

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
#[instruction(root: [u8; 24], rec_root: [u8; 24])]
pub struct Create<'info> {
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
#[instruction(tree_idx: u64)]
pub struct CacheSubtree<'info> {
    #[account(
        seeds = [ACCOUNT_SEED, account.seed.as_ref()],
        bump = account.bump,
    )]
    pub account: Account<'info, CchsAccount>,
    /// Cache slot for bottom subtree `tree_idx` in the current epoch.
    /// Created (zeroed) here if it does not exist yet.
    #[account(
        init_if_needed,
        payer = payer,
        seeds = [
            CACHE_SEED,
            account.key().as_ref(),
            &account.epoch.to_le_bytes(),
            &tree_idx.to_le_bytes(),
        ],
        bump,
        space = 8 + SubtreeCache::INIT_SPACE,
    )]
    pub cache: Account<'info, SubtreeCache>,
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
    /// epoch. Must already exist (filled by `cache_subtree`); a zero root is
    /// rejected with `MissingTopLayer`.
    #[account(
        seeds = [
            CACHE_SEED,
            account.key().as_ref(),
            &account.epoch.to_le_bytes(),
            &(account.next_idx >> 10).to_le_bytes(),
        ],
        bump,
    )]
    pub cache: Account<'info, SubtreeCache>,
    /// CHECK: the program invoked by the CPI; its key is bound into the
    /// signed digest and it is required to be executable.
    pub target_program: UncheckedAccount<'info>,
    // remaining_accounts: every account of the inner instruction (not the
    // target program itself), including `account` and/or the vault PDA when
    // the inner instruction needs them.
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
    /// Immutable PDA seed (the root given at creation).
    pub seed: [u8; 24],
    /// Top-layer tree root. Rotatable only via `recover`.
    pub root: [u8; 24],
    /// Recovery tree root (single layer, height 8).
    pub rec_root: [u8; 24],
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
    pub root: [u8; 24],
}

// ----------------------------------------------------------------- events

#[event]
pub struct Initialized {
    pub account: Pubkey,
    pub root: [u8; 24],
    pub rec_root: [u8; 24],
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
    pub subtree_root: [u8; 24],
}

#[event]
pub struct Recovered {
    pub account: Pubkey,
    pub epoch: u64,
    pub new_root: [u8; 24],
    pub new_rec_root: [u8; 24],
}

// ----------------------------------------------------------------- errors

#[error_code]
pub enum AegisError {
    #[msg("signature capacity exhausted")]
    Exhausted,
    #[msg("subtree not cached; call cache_subtree first")]
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
    #[msg("cache slot already holds a different subtree root")]
    CacheConflict,
    #[msg("target program account is not executable")]
    TargetNotExecutable,
}
