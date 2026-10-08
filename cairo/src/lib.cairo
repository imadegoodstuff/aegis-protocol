// Aegis Starknet account — stub for v0.1.
//
// This mirrors the EVM AegisAccount contract in Cairo 1 for Starknet.
// It is intentionally a stub so the surface area is defined early.
// Real SPHINCS+ verification in Cairo is a 4-week implementation
// (see roadmap item cairo-sphincs-verifier).
//
// Invariants that must hold identically to the EVM contract:
//   - pq_pk_hash is set at construction, cannot change
//   - guardian is set at construction, cannot change
//   - ecdsa_owner is set at construction, cannot change (used for StarkNet
//     signature fallback since there is no secp256k1 ECDSA natively; we use
//     Stark signature as the fallback here)
//   - 7-day timelock on emergency exit
//   - PQ sig can cancel a pending exit
//
// Starknet address derivation differs from EVM. Same seed => different address
// on Starknet. This is physically unavoidable and documented in SPEC.md.

#[starknet::contract]
mod AegisAccount {
    use starknet::ContractAddress;
    use starknet::get_block_timestamp;
    use starknet::get_caller_address;

    const VERSION: felt252 = '0.1.0';
    const TIMELOCK: u64 = 604800; // 7 days
    const PROTOCOL_FEE_BPS: u64 = 1000;
    const MAX_FEE_BPS: u64 = 2000;

    #[storage]
    struct Storage {
        // immutable-at-construction (Cairo has no `immutable` keyword; enforce in logic)
        pq_pk_hash: felt252,
        guardian: ContractAddress,
        ecdsa_owner: ContractAddress,
        verifier: ContractAddress,
        fee_collector: ContractAddress,
        // mutable
        nonce: u64,
        exit_timestamp: u64,
        exit_nonce: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Executed: Executed,
        EmergencyExitInitiated: EmergencyExitInitiated,
        EmergencyExitFinalized: EmergencyExitFinalized,
    }

    #[derive(Drop, starknet::Event)]
    struct Executed { nonce: u64, target: ContractAddress }

    #[derive(Drop, starknet::Event)]
    struct EmergencyExitInitiated { unlock_at: u64, exit_nonce: u64 }

    #[derive(Drop, starknet::Event)]
    struct EmergencyExitFinalized { guardian: ContractAddress }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pq_pk_hash: felt252,
        guardian: ContractAddress,
        ecdsa_owner: ContractAddress,
        verifier: ContractAddress,
        fee_collector: ContractAddress,
    ) {
        self.pq_pk_hash.write(pq_pk_hash);
        self.guardian.write(guardian);
        self.ecdsa_owner.write(ecdsa_owner);
        self.verifier.write(verifier);
        self.fee_collector.write(fee_collector);
    }

    // -- TODO: implement execute / initiate_exit / cancel_exit / finalize_exit --
    // Current status: contract declares the storage shape and constructor only.
    // Full implementation pending the Cairo SPHINCS+ verifier (roadmap:
    // https://github.com/<org>/aegis/issues/cairo-sphincs-verifier).
}
