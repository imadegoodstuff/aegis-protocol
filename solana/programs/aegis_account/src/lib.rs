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
//! * `execute(idx, ..)` carries only the bottom layer for the signer-chosen
//!   leaf `idx` (`idx >= next_idx`, afterwards `next_idx = idx + 1`),
//!   recomputes `r0` from it and requires the cache PDA of subtree
//!   `idx >> 10` to hold exactly that value. No top layer is ever accepted
//!   here, which is what keeps the instruction inside one packet; a jump
//!   into an unregistered subtree fails with `MissingTopLayer` until
//!   `cache_subtree` has landed for it.
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
    /// the digest of `(account, nonce, idx, target_program, ix_data)`.
    ///
    /// `idx` is the leaf the signer chose. It must be `>= next_idx`
    /// (`IndexUsed` otherwise) and `< 2^20` (`Exhausted`); on success
    /// `next_idx = idx + 1`, so every lower leaf is abandoned forever. Only
    /// the signer can skip, because `idx` is bound into the digest. The
    /// `cache` account is the PDA of subtree `idx >> 10`; the bottom subtree
    /// root recomputed from the signature must equal the value stored there
    /// by `cache_subtree`. Instruction data:
    /// 8 + 8 + 624 + 240 + 4 + ix_data.len() bytes.
    ///
    /// The account PDA and the vault PDA both sign the CPI.
    pub fn execute<'info>(
        ctx: Context<'_, '_, 'info, 'info, Execute<'info>>,
        idx: u64,
        l0_wots: [[u8; 24]; 26],
        l0_auth: [[u8; 24]; 10],
        ix_data: Vec<u8>,
    ) -> Result<()> {
        let account_key = ctx.accounts.account.key();
        let target_program = ctx.accounts.target_program.key();
        require!(ctx.accounts.target_program.executable, AegisError::TargetNotExecutable);

        let acc = &mut ctx.accounts.account;
        let mut state = load_state(acc);
        // Index discipline first, before any hashing.
        state.check_idx(idx).map_err(map_err)?;

        let cached = ctx.accounts.cache.root;
        require!(cached != ZERO, AegisError::MissingTopLayer);

        let mut h = SolSha256::default();
        let msg = execute_digest(&mut h, &account_key, acc.nonce, idx, &target_program, &ix_data);

        let outcome = state
            .execute_cached(&mut h, idx, &msg, LayerSig { wots: &l0_wots, auth: &l0_auth }, cached)
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
        CchsError::IndexUsed => error!(AegisError::IndexUsed),
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
#[instruction(idx: u64)]
pub struct Execute<'info> {
    #[account(
        mut,
        seeds = [ACCOUNT_SEED, account.seed.as_ref()],
        bump = account.bump,
    )]
    pub account: Account<'info, CchsAccount>,
    /// Cache slot for the bottom subtree of the requested leaf `idx` in the
    /// current epoch. Must already exist (filled by `cache_subtree`); a zero
    /// root is rejected with `MissingTopLayer`.
    #[account(
        seeds = [
            CACHE_SEED,
            account.key().as_ref(),
            &account.epoch.to_le_bytes(),
            &(idx >> 10).to_le_bytes(),
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
    /// Lowest leaf index still available in [0, 2^20); every leaf below it
    /// is consumed or abandoned.
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
    #[msg("leaf index already used or abandoned")]
    IndexUsed,
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

// ------------------------------------------------------------------ tests

/// Host-side replay of `evm/test/fixtures/cchs-c-20.json` through the same
/// core calls and in the same order as the `cache_subtree` and `execute`
/// handlers, using the program's `SolSha256` (the `sol_sha256` syscall is a
/// native SHA-256 on the host). The fixture digests bind a fixed account and
/// the EVM-style call hash, so the signatures are fed in as 24-byte messages;
/// the Solana digest itself is checked separately.
#[cfg(test)]
mod tests {
    use super::*;
    use cchs_core::compact::{bottom_root, H};
    use serde_json::Value;

    const FIXTURE: &str = include_str!("../../../../evm/test/fixtures/cchs-c-20.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("fixture parses")
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn b24(v: &Value) -> Hash {
        let bytes = hex_bytes(v.as_str().expect("hex string"));
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    struct Layer {
        wots: [Hash; LEN],
        auth: [Hash; H],
    }

    impl Layer {
        fn from_json(v: &Value) -> Layer {
            let w: Vec<Hash> = v["wots"].as_array().unwrap().iter().map(b24).collect();
            let a: Vec<Hash> = v["auth"].as_array().unwrap().iter().map(b24).collect();
            let mut wots = [[0u8; N]; LEN];
            wots.copy_from_slice(&w);
            let mut auth = [[0u8; N]; H];
            auth.copy_from_slice(&a);
            Layer { wots, auth }
        }
        fn sig(&self) -> LayerSig<'_> {
            LayerSig { wots: &self.wots, auth: &self.auth }
        }
    }

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
                idx: v["idx"].as_u64().unwrap(),
                nonce: v["nonce"].as_u64().unwrap(),
                digest: b24(&v["digest"]),
                l0: Layer::from_json(&v["l0"]),
                l1: if v["l1"].is_null() { None } else { Some(Layer::from_json(&v["l1"])) },
            }
        }
    }

    /// In-memory stand-in for the `SubtreeCache` PDAs of one epoch.
    #[derive(Default)]
    struct Caches(std::collections::BTreeMap<u64, Hash>);

    impl Caches {
        fn root(&self, tree_idx: u64) -> Hash {
            self.0.get(&tree_idx).copied().unwrap_or(ZERO)
        }
    }

    /// Mirrors the `cache_subtree` handler.
    fn cache_subtree(
        root: &Hash,
        caches: &mut Caches,
        tree_idx: u64,
        l1: &Layer,
        r0: Hash,
    ) -> std::result::Result<(), AegisError> {
        if r0 == ZERO {
            return Err(AegisError::ZeroRoot);
        }
        let mut h = SolSha256::default();
        verify_top_layer(&mut h, root, tree_idx, &r0, l1.sig()).map_err(core_err)?;
        let slot = caches.root(tree_idx);
        if !(slot == ZERO || slot == r0) {
            return Err(AegisError::CacheConflict);
        }
        caches.0.insert(tree_idx, r0);
        Ok(())
    }

    /// Mirrors the `execute` handler: index check, cache presence, verify.
    fn execute(
        state: &mut CchsState,
        caches: &Caches,
        idx: u64,
        msg: &Hash,
        l0: &Layer,
    ) -> std::result::Result<Hash, AegisError> {
        state.check_idx(idx).map_err(core_err)?;
        let cached = caches.root(idx >> 10);
        if cached == ZERO {
            return Err(AegisError::MissingTopLayer);
        }
        let mut h = SolSha256::default();
        let out = state.execute_cached(&mut h, idx, msg, l0.sig(), cached).map_err(core_err)?;
        Ok(out.subtree_root)
    }

    fn core_err(e: CchsError) -> AegisError {
        match e {
            CchsError::Exhausted => AegisError::Exhausted,
            CchsError::IndexUsed => AegisError::IndexUsed,
            CchsError::MissingTopLayer => AegisError::MissingTopLayer,
            CchsError::BadSubtreeRoot => AegisError::BadSubtreeRoot,
            CchsError::BadTopRoot => AegisError::BadTopRoot,
            CchsError::BadRecovery => AegisError::BadRecovery,
            CchsError::ZeroRoot => AegisError::ZeroRoot,
            CchsError::BadLength => AegisError::BadLength,
        }
    }

    fn err_code(e: AegisError) -> u32 {
        e as u32
    }

    fn assert_err(r: std::result::Result<Hash, AegisError>, want: AegisError) {
        match r {
            Ok(_) => panic!("expected {want:?}, got Ok"),
            Err(e) => assert_eq!(err_code(e), err_code(want)),
        }
    }

    /// Fresh account with subtree 0 registered and `ops[0]` executed.
    fn after_first_op(f: &Value) -> (CchsState, Caches, Hash) {
        let root = b24(&f["root"]);
        let bottom0 = b24(&f["bottomRoot0"]);
        let mut state = CchsState::new(root, b24(&f["recRoot"])).unwrap();
        let mut caches = Caches::default();
        let op0 = Op::from_json(&f["ops"][0]);
        cache_subtree(&root, &mut caches, 0, op0.l1.as_ref().unwrap(), bottom0).unwrap();
        let r0 = execute(&mut state, &caches, op0.idx, &op0.digest, &op0.l0).unwrap();
        assert_eq!(r0, bottom0);
        assert_eq!(state.next_idx, 1);
        (state, caches, bottom0)
    }

    #[test]
    fn sequential_ops_follow_fixture() {
        let f = fixture();
        let (mut state, caches, bottom0) = after_first_op(&f);
        for i in 1..3 {
            let op = Op::from_json(&f["ops"][i]);
            assert_eq!(op.idx, state.next_idx);
            assert_eq!(op.nonce, state.nonce);
            let r0 = execute(&mut state, &caches, op.idx, &op.digest, &op.l0).unwrap();
            assert_eq!(r0, bottom0);
            assert_eq!(state.next_idx, i as u64 + 1);
            assert_eq!(state.nonce, i as u64 + 1);
        }
    }

    #[test]
    fn skip_within_subtree_then_jump_to_fresh_subtree() {
        let f = fixture();
        let root = b24(&f["root"]);
        let bottom1 = b24(&f["bottomRoot1"]);
        let (mut state, mut caches, bottom0) = after_first_op(&f);

        // skip.ops[0]: idx 5, nonce 1, cached path.
        let op5 = Op::from_json(&f["skip"]["ops"][0]);
        assert_eq!(op5.idx, 5);
        assert_eq!(op5.nonce, state.nonce);
        assert!(op5.l1.is_none());
        let r0 = execute(&mut state, &caches, op5.idx, &op5.digest, &op5.l0).expect("skip to leaf 5");
        assert_eq!(r0, bottom0);
        assert_eq!(state.next_idx, 6);
        assert_eq!(state.nonce, 2);

        // skip.ops[1]: idx 1024, nonce 2, first leaf of subtree 1.
        let op1024 = Op::from_json(&f["skip"]["ops"][1]);
        assert_eq!(op1024.idx, 1024);
        assert_eq!(op1024.nonce, state.nonce);
        let l1 = op1024.l1.as_ref().expect("cross-subtree jump carries l1");

        // The client computes r0 for subtree 1 from the bottom layer...
        let mut h = SolSha256::default();
        let r0 = bottom_root(&mut h, op1024.idx, &op1024.digest, op1024.l0.sig()).unwrap();
        assert_eq!(r0, bottom1, "bottom root of subtree 1 equals bottomRoot1");
        // ...registers it with the top layer, then executes on the cached path.
        cache_subtree(&root, &mut caches, 1, l1, bottom1).expect("cache fill for subtree 1");
        assert_eq!(caches.root(1), bottom1);
        let r0 = execute(&mut state, &caches, op1024.idx, &op1024.digest, &op1024.l0).expect("execute at leaf 1024");
        assert_eq!(r0, bottom1);
        assert_eq!(state.next_idx, 1025);
        assert_eq!(state.nonce, 3);
    }

    #[test]
    fn index_below_next_idx_is_rejected() {
        let f = fixture();
        let (mut state, caches, _) = after_first_op(&f);
        let op5 = Op::from_json(&f["skip"]["ops"][0]);
        execute(&mut state, &caches, op5.idx, &op5.digest, &op5.l0).unwrap();
        assert_eq!(state.next_idx, 6);

        // ops[1] (idx 1) lies in the abandoned range; replaying leaf 5 too.
        let op1 = Op::from_json(&f["ops"][1]);
        assert_err(execute(&mut state, &caches, op1.idx, &op1.digest, &op1.l0), AegisError::IndexUsed);
        assert_err(execute(&mut state, &caches, op5.idx, &op5.digest, &op5.l0), AegisError::IndexUsed);
        assert_eq!(state.next_idx, 6, "state untouched on error");
        assert_eq!(state.nonce, 2);

        // Upper bound.
        assert_err(execute(&mut state, &caches, 1 << 20, &op5.digest, &op5.l0), AegisError::Exhausted);
    }

    #[test]
    fn jump_to_fresh_subtree_without_cache_is_rejected() {
        let f = fixture();
        let (mut state, caches, _) = after_first_op(&f);
        let op1024 = Op::from_json(&f["skip"]["ops"][1]);
        assert_err(
            execute(&mut state, &caches, op1024.idx, &op1024.digest, &op1024.l0),
            AegisError::MissingTopLayer,
        );
        assert_eq!(state.next_idx, 1);
        assert_eq!(state.nonce, 1);
    }

    #[test]
    fn signature_is_bound_to_its_index() {
        let f = fixture();
        let (mut state, caches, _) = after_first_op(&f);
        // The leaf-5 signature submitted at leaf 6 with the same digest.
        let op5 = Op::from_json(&f["skip"]["ops"][0]);
        assert_err(execute(&mut state, &caches, 6, &op5.digest, &op5.l0), AegisError::BadSubtreeRoot);
        assert_eq!(state.next_idx, 1);
    }

    #[test]
    fn redundant_cache_fill_is_idempotent() {
        // The split-flow counterpart of "a redundant top layer is ignored":
        // registering an already registered subtree with the same proof is a
        // no-op, and a later op in that subtree still executes.
        let f = fixture();
        let root = b24(&f["root"]);
        let (mut state, mut caches, bottom0) = after_first_op(&f);
        let op0 = Op::from_json(&f["ops"][0]);
        cache_subtree(&root, &mut caches, 0, op0.l1.as_ref().unwrap(), bottom0).expect("idempotent");
        assert_eq!(caches.root(0), bottom0);

        let op1 = Op::from_json(&f["ops"][1]);
        execute(&mut state, &caches, op1.idx, &op1.digest, &op1.l0).unwrap();
        assert_eq!(state.next_idx, 2);

        // A different root for a registered slot is a conflict (and cannot
        // pass the top layer anyway).
        let mut other = bottom0;
        other[0] ^= 1;
        match cache_subtree(&root, &mut caches, 0, op0.l1.as_ref().unwrap(), other) {
            Err(e) => assert_eq!(err_code(e), err_code(AegisError::BadTopRoot)),
            Ok(()) => panic!("wrong root registered"),
        }
    }

    #[test]
    fn solana_digest_binds_the_index() {
        let account = Pubkey::new_from_array([0xCCu8; 32]);
        let target = Pubkey::new_from_array([0x01u8; 32]);
        let mut h = SolSha256::default();
        let d0 = execute_digest(&mut h, &account, 1, 0, &target, &[1, 2, 3]);
        let d5 = execute_digest(&mut h, &account, 1, 5, &target, &[1, 2, 3]);
        let d0_again = execute_digest(&mut h, &account, 1, 0, &target, &[1, 2, 3]);
        assert_eq!(d0, d0_again);
        assert_ne!(d0, d5, "the leaf index is part of the digest");
    }
}
