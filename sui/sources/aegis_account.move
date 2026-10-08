/// Aegis — post-quantum smart account on Sui (Move 2024).
module aegis::aegis_account {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use sui::clock::{Self, Clock};

    const TIMELOCK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

    // ---- error codes ----
    const EBadNonce:         u64 = 0;
    const EInvalidPqSig:     u64 = 1;
    const ENoPendingExit:    u64 = 2;
    const ETimelockNotReady: u64 = 3;
    const EWrongGuardian:    u64 = 4;

    /// Shared object owned by nobody; auth is purely via PQ sig verification.
    public struct AegisAccount has key {
        id: UID,
        pq_pk_hash: vector<u8>,           // 32 bytes
        guardian: address,
        fallback_pubkey_hash: vector<u8>, // 32 bytes
        fee_collector: address,
        nonce: u64,
        exit_timestamp_ms: u64,
        exit_nonce: u64,
    }

    public struct Executed              has copy, drop { nonce: u64 }
    public struct EmergencyExitInit     has copy, drop { unlock_at_ms: u64, exit_nonce: u64 }
    public struct EmergencyExitCancel   has copy, drop { exit_nonce: u64 }
    public struct EmergencyExitFinalize has copy, drop { guardian: address }

    /// Create a new shared Aegis account.
    public entry fun create(
        pq_pk_hash: vector<u8>,
        guardian: address,
        fallback_pubkey_hash: vector<u8>,
        fee_collector: address,
        ctx: &mut TxContext,
    ) {
        let acct = AegisAccount {
            id: object::new(ctx),
            pq_pk_hash,
            guardian,
            fallback_pubkey_hash,
            fee_collector,
            nonce: 0,
            exit_timestamp_ms: 0,
            exit_nonce: 0,
        };
        transfer::share_object(acct);
    }

    /// Execute: PQ sig gated. TODO(v0.2): actually verify.
    public entry fun execute(
        acct: &mut AegisAccount,
        provided_nonce: u64,
        _pq_pk: vector<u8>,
        _pq_sig: vector<u8>,
        _payload: vector<u8>,
    ) {
        assert!(provided_nonce == acct.nonce + 1, EBadNonce);
        // TODO: hash(pq_pk) == acct.pq_pk_hash; sphincs_verify
        acct.nonce = provided_nonce;
        event::emit(Executed { nonce: provided_nonce });
    }

    public entry fun initiate_emergency_exit(
        acct: &mut AegisAccount,
        _fallback_sig: vector<u8>,
        clock: &Clock,
    ) {
        // TODO: verify fallback sig (ed25519 under acct.fallback_pubkey_hash)
        let now = clock::timestamp_ms(clock);
        let unlock = now + TIMELOCK_MS;
        acct.exit_timestamp_ms = unlock;
        event::emit(EmergencyExitInit { unlock_at_ms: unlock, exit_nonce: acct.exit_nonce });
    }

    public entry fun cancel_emergency_exit(
        acct: &mut AegisAccount,
        _pq_pk: vector<u8>,
        _pq_sig: vector<u8>,
    ) {
        assert!(acct.exit_timestamp_ms != 0, ENoPendingExit);
        // TODO: verify PQ sig
        acct.exit_timestamp_ms = 0;
        acct.exit_nonce = acct.exit_nonce + 1;
        event::emit(EmergencyExitCancel { exit_nonce: acct.exit_nonce });
    }

    public entry fun finalize_emergency_exit(
        acct: &mut AegisAccount,
        clock: &Clock,
    ) {
        assert!(acct.exit_timestamp_ms != 0, ENoPendingExit);
        assert!(clock::timestamp_ms(clock) >= acct.exit_timestamp_ms, ETimelockNotReady);
        // TODO(v0.2): sweep owned Coin<T> objects to acct.guardian via dynamic field iteration
        acct.exit_timestamp_ms = 0;
        acct.exit_nonce = acct.exit_nonce + 1;
        event::emit(EmergencyExitFinalize { guardian: acct.guardian });
    }

    // ---- views ----
    public fun nonce(a: &AegisAccount): u64 { a.nonce }
    public fun exit_timestamp_ms(a: &AegisAccount): u64 { a.exit_timestamp_ms }
    public fun guardian(a: &AegisAccount): address { a.guardian }

    #[allow(unused_use, unused_function)]
    fun _unused() { let _ = tx_context::sender; }
}
