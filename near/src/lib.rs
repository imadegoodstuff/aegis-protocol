//! Aegis — post-quantum smart account for NEAR.
//! Deploy one contract per user as a subaccount:
//!   <pq_pk_hash_hex[..16]>.aegis.near
//!
//! State machine mirrors `evm/src/AegisAccount.sol`.

use near_sdk::{env, log, near, store::LookupMap, AccountId, Promise, NearToken};

const TIMELOCK_NS: u64 = 7u64 * 24 * 60 * 60 * 1_000_000_000;
pub const PROTOCOL_FEE_BPS: u16 = 1000;
pub const MAX_FEE_BPS: u16     = 2000;

#[near(contract_state)]
pub struct AegisAccount {
    pub pq_pk_hash:          [u8; 32],
    pub guardian:            AccountId,
    pub fallback_pubkey:     Vec<u8>,
    pub fee_collector:       AccountId,
    pub nonce:               u64,
    pub exit_timestamp_ns:   u64,
    pub exit_nonce:          u64,
    pub initialized:         bool,
    #[allow(dead_code)]
    pub reserved:            LookupMap<String, u64>,
}

impl Default for AegisAccount {
    fn default() -> Self {
        Self {
            pq_pk_hash: [0u8; 32],
            guardian: "nobody.near".parse().unwrap(),
            fallback_pubkey: Vec::new(),
            fee_collector: "nobody.near".parse().unwrap(),
            nonce: 0,
            exit_timestamp_ns: 0,
            exit_nonce: 0,
            initialized: false,
            reserved: LookupMap::new(b"r"),
        }
    }
}

#[near]
impl AegisAccount {
    /// One-shot initializer. Immutable after this call succeeds.
    #[init]
    pub fn new(
        pq_pk_hash: [u8; 32],
        guardian: AccountId,
        fallback_pubkey: Vec<u8>,
        fee_collector: AccountId,
    ) -> Self {
        Self {
            pq_pk_hash, guardian, fallback_pubkey, fee_collector,
            nonce: 0, exit_timestamp_ns: 0, exit_nonce: 0,
            initialized: true,
            reserved: LookupMap::new(b"r"),
        }
    }

    /// Execute: PQ-sig gated. TODO(v0.2): actually verify.
    pub fn execute(
        &mut self,
        provided_nonce: u64,
        _pq_pk: Vec<u8>,
        _pq_sig: Vec<u8>,
        target: AccountId,
        attached_yocto: String,     // u128 as string (NEAR convention)
        method: String,
        args_base64: String,
        gas_tgas: u64,
    ) -> Promise {
        assert!(self.initialized, "not initialized");
        assert_eq!(provided_nonce, self.nonce + 1, "bad nonce");
        // TODO: sha256(pq_pk) == pq_pk_hash; sphincs_verify
        self.nonce = provided_nonce;
        log!("Executed nonce={}", provided_nonce);

        let args = near_sdk::base64::engine::general_purpose::STANDARD
            .decode(args_base64.as_bytes())
            .expect("bad base64");
        let yocto: u128 = attached_yocto.parse().unwrap_or(0);
        Promise::new(target).function_call(
            method,
            args,
            NearToken::from_yoctonear(yocto),
            near_sdk::Gas::from_tgas(gas_tgas),
        )
    }

    pub fn initiate_emergency_exit(&mut self, _fallback_sig: Vec<u8>) {
        // TODO: verify ed25519 sig under fallback_pubkey
        let now = env::block_timestamp();
        self.exit_timestamp_ns = now + TIMELOCK_NS;
        log!("Exit initiated unlock_at_ns={}", self.exit_timestamp_ns);
    }

    pub fn cancel_emergency_exit(&mut self, _pq_pk: Vec<u8>, _pq_sig: Vec<u8>) {
        assert!(self.exit_timestamp_ns != 0, "no pending exit");
        // TODO: verify PQ sig
        self.exit_timestamp_ns = 0;
        self.exit_nonce += 1;
    }

    /// Sweeps all native NEAR balance to guardian. FT sweeps go through separate
    /// ft_transfer promises in a batched call orchestrated client-side.
    pub fn finalize_emergency_exit(&mut self) -> Promise {
        assert!(self.exit_timestamp_ns != 0, "no pending exit");
        let now = env::block_timestamp();
        assert!(now >= self.exit_timestamp_ns, "timelock not elapsed");

        let balance = env::account_balance();
        self.exit_timestamp_ns = 0;
        self.exit_nonce += 1;
        Promise::new(self.guardian.clone()).transfer(balance)
    }

    // ---- views ----
    pub fn get_nonce(&self) -> u64 { self.nonce }
    pub fn get_exit_timestamp_ns(&self) -> u64 { self.exit_timestamp_ns }
    pub fn get_guardian(&self) -> AccountId { self.guardian.clone() }

    pub fn get_pq_pk_hash(&self) -> String {
        hex::encode(self.pq_pk_hash)
    }
}

// avoid pulling the `hex` crate just for one display helper.
mod hex {
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        let mut s = String::with_capacity(b.as_ref().len() * 2);
        for byte in b.as_ref() {
            use core::fmt::Write;
            write!(&mut s, "{:02x}", byte).unwrap();
        }
        s
    }
}
