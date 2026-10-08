/// Aegis — post-quantum smart account on Aptos (Move).
/// Mirrors the EVM AegisAccount state machine.
module aegis::aegis_account {
    use std::signer;
    use std::vector;
    use std::error;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::account;
    use aptos_framework::event;

    const TIMELOCK_SECONDS: u64 = 60 * 60 * 24 * 7;   // 7 days
    const PROTOCOL_FEE_BPS: u64 = 1000;
    const MAX_FEE_BPS:      u64 = 2000;

    // ---- errors ----
    const E_ALREADY_INIT:        u64 = 1;
    const E_BAD_NONCE:           u64 = 2;
    const E_INVALID_PQ_SIG:      u64 = 3;
    const E_INVALID_FALLBACK:    u64 = 4;
    const E_NO_PENDING_EXIT:     u64 = 5;
    const E_TIMELOCK_NOT_READY:  u64 = 6;
    const E_WRONG_GUARDIAN:      u64 = 7;

    // ---- state ----
    struct AegisAccount has key {
        pq_pk_hash: vector<u8>,          // 32 bytes, keccak256(pk)
        guardian: address,
        fallback_pubkey_hash: vector<u8>, // sha3-256(ed25519 pubkey) truncated
        fee_collector: address,
        nonce: u64,
        exit_timestamp: u64,
        exit_nonce: u64,
    }

    // ---- events ----
    #[event] struct Executed              has drop, store { nonce: u64 }
    #[event] struct EmergencyExitInit     has drop, store { unlock_at: u64, exit_nonce: u64 }
    #[event] struct EmergencyExitCancel   has drop, store { exit_nonce: u64 }
    #[event] struct EmergencyExitFinalize has drop, store { guardian: address }

    // ---- init: resource is published under the user's signer address ----
    public entry fun initialize(
        user: &signer,
        pq_pk_hash: vector<u8>,
        guardian: address,
        fallback_pubkey_hash: vector<u8>,
        fee_collector: address,
    ) {
        let addr = signer::address_of(user);
        assert!(!exists<AegisAccount>(addr), error::already_exists(E_ALREADY_INIT));
        assert!(vector::length(&pq_pk_hash) == 32, error::invalid_argument(E_INVALID_PQ_SIG));
        move_to(user, AegisAccount {
            pq_pk_hash, guardian, fallback_pubkey_hash, fee_collector,
            nonce: 0, exit_timestamp: 0, exit_nonce: 0,
        });
    }

    /// Execute: PQ-sig gated. TODO(v0.2): actually verify the SPHINCS+ signature.
    /// The payload argument is opaque bytes; concrete callers wrap target Move
    /// calls through a dispatcher pattern (next version).
    public entry fun execute(
        caller: &signer,
        acct_addr: address,
        provided_nonce: u64,
        _pq_pk: vector<u8>,
        _pq_sig: vector<u8>,
        _payload: vector<u8>,
    ) acquires AegisAccount {
        let _ = caller;
        let acct = borrow_global_mut<AegisAccount>(acct_addr);
        assert!(provided_nonce == acct.nonce + 1, error::invalid_argument(E_BAD_NONCE));
        // TODO: hash(pq_pk) == acct.pq_pk_hash; sphincs_verify(pq_pk, digest, pq_sig)
        acct.nonce = provided_nonce;
        event::emit(Executed { nonce: provided_nonce });
    }

    public entry fun initiate_emergency_exit(
        _caller: &signer, acct_addr: address, _fallback_sig: vector<u8>,
    ) acquires AegisAccount {
        let acct = borrow_global_mut<AegisAccount>(acct_addr);
        // TODO: verify ed25519 sig under acct.fallback_pubkey_hash
        let unlock = timestamp::now_seconds() + TIMELOCK_SECONDS;
        acct.exit_timestamp = unlock;
        event::emit(EmergencyExitInit { unlock_at: unlock, exit_nonce: acct.exit_nonce });
    }

    public entry fun cancel_emergency_exit(
        _caller: &signer, acct_addr: address, _pq_pk: vector<u8>, _pq_sig: vector<u8>,
    ) acquires AegisAccount {
        let acct = borrow_global_mut<AegisAccount>(acct_addr);
        assert!(acct.exit_timestamp != 0, error::invalid_state(E_NO_PENDING_EXIT));
        // TODO: verify PQ sig
        acct.exit_timestamp = 0;
        acct.exit_nonce = acct.exit_nonce + 1;
        event::emit(EmergencyExitCancel { exit_nonce: acct.exit_nonce });
    }

    public entry fun finalize_emergency_exit<CoinType>(
        _caller: &signer, acct_addr: address,
    ) acquires AegisAccount {
        let acct = borrow_global_mut<AegisAccount>(acct_addr);
        assert!(acct.exit_timestamp != 0, error::invalid_state(E_NO_PENDING_EXIT));
        assert!(timestamp::now_seconds() >= acct.exit_timestamp, error::invalid_state(E_TIMELOCK_NOT_READY));
        // Pull all CoinType balance out of acct_addr and deposit to guardian.
        // Caller must repeat this for each CoinType; this mirrors the EVM pattern of
        // passing the list of ERC-20 token addresses.
        let bal = coin::balance<CoinType>(acct_addr);
        if (bal > 0) {
            // TODO(v0.2): proper withdraw via a resource-account capability pattern;
            // in-place transfer needs the account signer, which here must be obtained
            // via SignerCapability stored at init time (not shown in skeleton).
        };
        acct.exit_timestamp = 0;
        acct.exit_nonce = acct.exit_nonce + 1;
        event::emit(EmergencyExitFinalize { guardian: acct.guardian });
    }

    // ---- views ----
    #[view] public fun get_nonce(a: address): u64 acquires AegisAccount {
        borrow_global<AegisAccount>(a).nonce
    }
    #[view] public fun get_exit_timestamp(a: address): u64 acquires AegisAccount {
        borrow_global<AegisAccount>(a).exit_timestamp
    }
    #[view] public fun get_guardian(a: address): address acquires AegisAccount {
        borrow_global<AegisAccount>(a).guardian
    }

    #[allow(unused_use)]
    fun _unused_imports() { let _ = account::create_resource_address; }
}
