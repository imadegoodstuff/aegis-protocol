//! Aegis post-quantum smart account for Solana.
//!
//! Design mirrors `evm/src/AegisAccount.sol`:
//!   - per-user PDA account (seed = ["aegis-v1", pq_pk_hash, guardian])
//!   - stores pq_pk_hash, guardian, fallback_pubkey, nonce, exit_timestamp as immutable
//!     (set once in `initialize`; subsequent writes must verify PQ sig)
//!   - `execute`           : PQ-sig gated; dispatches a CPI call
//!   - `initiate_exit`     : Ed25519-sig from fallback_pubkey, starts 7d timelock
//!   - `cancel_exit`       : PQ sig; vetoes a pending exit (defense vs. stolen Ed25519)
//!   - `finalize_exit`     : after TIMELOCK, drains lamports + listed SPL tokens to guardian
//!
//! The SPHINCS+ verification itself is a `TODO` stub. Solana BPF has a 200K
//! compute-unit limit per instruction and ~4KB stack; a plain SPHINCS+-192s
//! verify (~5M hashes) is infeasible in-program. Options:
//!   A. Use the SIMD-0152 syscall for user-defined precompiles (when available)
//!   B. Precompute a Merkle-batched SPHINCS+ verifier split across many txs
//!   C. Use SHRINCS (Kudinov–Nick) with ~324B sigs — much cheaper to verify
//!
//! v0.1 ships the state machine and account layout; full verifier wires in via
//! an injectable `Verifier` trait so it can swap once a path above lands.

use anchor_lang::prelude::*;

declare_id!("AegisLnTkKk1x4VXx7v4p8h8rF1gKxh2M9W3PqV8n2bYz");

pub const TIMELOCK: i64 = 60 * 60 * 24 * 7; // 7 days
pub const PROTOCOL_FEE_BPS: u16 = 1000;
pub const MAX_FEE_BPS: u16 = 2000;

#[program]
pub mod aegis_account {
    use super::*;

    /// Create a new AegisAccount PDA. Writes immutable config once.
    pub fn initialize(
        ctx: Context<Initialize>,
        pq_pk_hash: [u8; 32],
        guardian: Pubkey,
        fallback_pubkey: Pubkey,
    ) -> Result<()> {
        let acc = &mut ctx.accounts.aegis;
        require!(acc.pq_pk_hash == [0u8; 32], AegisError::AlreadyInitialized);
        acc.pq_pk_hash = pq_pk_hash;
        acc.guardian = guardian;
        acc.fallback_pubkey = fallback_pubkey;
        acc.nonce = 0;
        acc.exit_timestamp = 0;
        acc.exit_nonce = 0;
        acc.bump = ctx.bumps.aegis;
        Ok(())
    }

    /// Execute a CPI authorized by a SPHINCS+ signature.
    ///
    /// TODO(v0.2): the `_pq_sig` and `_pq_pk` arguments are currently NOT
    /// verified. Wire up `aegis_verifier::verify` once the Solana SPHINCS+
    /// verifier path (SIMD-0152 syscall or SHRINCS variant) is implemented.
    pub fn execute(
        ctx: Context<Execute>,
        provided_nonce: u64,
        _pq_pk: Vec<u8>,
        _pq_sig: Vec<u8>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        let acc = &mut ctx.accounts.aegis;
        require!(provided_nonce == acc.nonce + 1, AegisError::BadNonce);
        // TODO: hash pq_pk, compare to acc.pq_pk_hash, call verifier
        // require!(hash(&_pq_pk) == acc.pq_pk_hash, AegisError::InvalidPqSig);
        // require!(verifier::verify(&_pq_pk, digest, &_pq_sig), AegisError::InvalidPqSig);
        acc.nonce = provided_nonce;
        emit!(Executed { nonce: provided_nonce, data_len: instruction_data.len() as u32 });
        Ok(())
    }

    pub fn initiate_emergency_exit(
        ctx: Context<Guard>,
        _fallback_sig: [u8; 64],
    ) -> Result<()> {
        // TODO: verify ed25519 signature by acc.fallback_pubkey over
        //       (chainid=solana, program_id, acc.key, acc.exit_nonce)
        let acc = &mut ctx.accounts.aegis;
        let now = Clock::get()?.unix_timestamp;
        acc.exit_timestamp = now + TIMELOCK;
        emit!(EmergencyExitInitiated { unlock_at: acc.exit_timestamp, exit_nonce: acc.exit_nonce });
        Ok(())
    }

    pub fn cancel_emergency_exit(
        ctx: Context<Guard>,
        _pq_pk: Vec<u8>,
        _pq_sig: Vec<u8>,
    ) -> Result<()> {
        // TODO: verify PQ sig over ("AEGIS_CANCEL_EXIT", program_id, acc.key, acc.exit_nonce)
        let acc = &mut ctx.accounts.aegis;
        require!(acc.exit_timestamp != 0, AegisError::NoPendingExit);
        acc.exit_timestamp = 0;
        acc.exit_nonce = acc.exit_nonce.checked_add(1).ok_or(AegisError::Overflow)?;
        emit!(EmergencyExitCancelled { exit_nonce: acc.exit_nonce });
        Ok(())
    }

    pub fn finalize_emergency_exit(ctx: Context<Finalize>) -> Result<()> {
        let acc = &mut ctx.accounts.aegis;
        require!(acc.exit_timestamp != 0, AegisError::NoPendingExit);
        let now = Clock::get()?.unix_timestamp;
        require!(now >= acc.exit_timestamp, AegisError::TimelockNotElapsed);

        // Transfer all lamports to guardian (SPL tokens handled by separate ix).
        let aegis_ai = ctx.accounts.aegis.to_account_info();
        let guardian_ai = ctx.accounts.guardian.to_account_info();
        require_keys_eq!(guardian_ai.key(), acc.guardian, AegisError::WrongGuardian);
        let lamports = **aegis_ai.lamports.borrow();
        **aegis_ai.lamports.borrow_mut() = 0;
        **guardian_ai.lamports.borrow_mut() += lamports;

        acc.exit_timestamp = 0;
        acc.exit_nonce = acc.exit_nonce.checked_add(1).ok_or(AegisError::Overflow)?;
        emit!(EmergencyExitFinalized { guardian: acc.guardian, lamports });
        Ok(())
    }
}

// ---- accounts ----

#[derive(Accounts)]
#[instruction(pq_pk_hash: [u8; 32], guardian: Pubkey, fallback_pubkey: Pubkey)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"aegis-v1", pq_pk_hash.as_ref(), guardian.as_ref()],
        bump,
        space = 8 + AegisAccount::SIZE,
    )]
    pub aegis: Account<'info, AegisAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut)]
    pub aegis: Account<'info, AegisAccount>,
    /// CHECK: fee receiver (immutable, matches program-constant). TODO.
    #[account(mut)]
    pub fee_collector: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Guard<'info> {
    #[account(mut)]
    pub aegis: Account<'info, AegisAccount>,
}

#[derive(Accounts)]
pub struct Finalize<'info> {
    #[account(mut)]
    pub aegis: Account<'info, AegisAccount>,
    /// CHECK: must equal acc.guardian; verified in handler
    #[account(mut)]
    pub guardian: UncheckedAccount<'info>,
}

// ---- state ----

#[account]
pub struct AegisAccount {
    pub pq_pk_hash: [u8; 32],
    pub guardian: Pubkey,
    pub fallback_pubkey: Pubkey,
    pub nonce: u64,
    pub exit_timestamp: i64,
    pub exit_nonce: u64,
    pub bump: u8,
}
impl AegisAccount {
    pub const SIZE: usize = 32 + 32 + 32 + 8 + 8 + 8 + 1;
}

// ---- events ----
#[event] pub struct Executed { pub nonce: u64, pub data_len: u32 }
#[event] pub struct EmergencyExitInitiated { pub unlock_at: i64, pub exit_nonce: u64 }
#[event] pub struct EmergencyExitCancelled { pub exit_nonce: u64 }
#[event] pub struct EmergencyExitFinalized { pub guardian: Pubkey, pub lamports: u64 }

// ---- errors ----
#[error_code]
pub enum AegisError {
    #[msg("account already initialized")]              AlreadyInitialized,
    #[msg("bad nonce")]                                 BadNonce,
    #[msg("invalid PQ signature")]                      InvalidPqSig,
    #[msg("no pending exit")]                           NoPendingExit,
    #[msg("timelock not elapsed")]                      TimelockNotElapsed,
    #[msg("wrong guardian account provided")]           WrongGuardian,
    #[msg("overflow")]                                  Overflow,
}
