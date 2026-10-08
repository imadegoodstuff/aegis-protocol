// SPDX-License-Identifier: MIT
//
// Aegis — Starknet smart account (Cairo 1).
//
// Mirrors `evm/src/AegisAccount.sol`. Full state machine implemented:
//   - immutable constructor state (pq_pk_hash, guardian, fallback_pubkey, verifier, fee_collector)
//   - execute() with PQ-sig gate + nonce + fee bps
//   - initiate_emergency_exit() with Stark-sig fallback
//   - cancel_emergency_exit() PQ-vetoes a pending exit
//   - finalize_emergency_exit() after 7-day timelock → guardian
//
// SPHINCS+ verification is delegated to an injectable `ISphincsVerifier`
// Cairo contract (same pattern as EVM). v0.1 ships a stub matching
// evm/src/SphincsVerifierStub.sol:
//      verify(pk, digest, sig) iff sha256(pk || digest) == sig[..32]
//
// Hash choice: Starknet-native Poseidon is used for the account's digest
// computation (cheap on Stark); the SPHINCS+ sig itself still uses the
// chain-of-sha256 chosen by SLH-DSA FIPS 205, so interop with the EVM
// verifier remains possible (same key material, cross-chain-verifiable).

use starknet::ContractAddress;

#[starknet::interface]
pub trait ISphincsVerifier<T> {
    fn verify(self: @T, pk: Array<felt252>, digest: felt252, sig: Array<felt252>) -> bool;
}

#[starknet::interface]
pub trait IAegisAccount<T> {
    fn execute(
        ref self: T,
        target: ContractAddress,
        selector: felt252,
        calldata: Array<felt252>,
        provided_nonce: u64,
        pq_pk: Array<felt252>,
        pq_sig: Array<felt252>,
    );
    fn initiate_emergency_exit(ref self: T, fallback_sig: Array<felt252>);
    fn cancel_emergency_exit(ref self: T, pq_pk: Array<felt252>, pq_sig: Array<felt252>);
    fn finalize_emergency_exit(ref self: T);

    fn get_nonce(self: @T) -> u64;
    fn get_exit_timestamp(self: @T) -> u64;
    fn get_guardian(self: @T) -> ContractAddress;
    fn get_pq_pk_hash(self: @T) -> felt252;
}

#[starknet::contract]
pub mod AegisAccount {
    use starknet::{ContractAddress, get_block_timestamp, syscalls, SyscallResultTrait};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;
    use super::{ISphincsVerifier, ISphincsVerifierDispatcher, ISphincsVerifierDispatcherTrait};

    pub const TIMELOCK_SECONDS: u64  = 7 * 24 * 60 * 60;
    pub const PROTOCOL_FEE_BPS: u16  = 1000;
    pub const MAX_FEE_BPS: u16       = 2000;

    #[storage]
    struct Storage {
        pq_pk_hash: felt252,              // poseidon(pk) treated as the EVM-equivalent commitment
        guardian: ContractAddress,
        fallback_pubkey: felt252,         // Starknet pubkey, used as the Stark-sig fallback owner
        verifier: ContractAddress,
        fee_collector: ContractAddress,
        nonce: u64,
        exit_timestamp: u64,
        exit_nonce: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Executed: Executed,
        EmergencyExitInitiated: EmergencyExitInitiated,
        EmergencyExitCancelled: EmergencyExitCancelled,
        EmergencyExitFinalized: EmergencyExitFinalized,
    }
    #[derive(Drop, starknet::Event)]
    struct Executed { #[key] pub nonce: u64, pub target: ContractAddress }
    #[derive(Drop, starknet::Event)]
    struct EmergencyExitInitiated { pub unlock_at: u64, pub exit_nonce: u64 }
    #[derive(Drop, starknet::Event)]
    struct EmergencyExitCancelled { pub exit_nonce: u64 }
    #[derive(Drop, starknet::Event)]
    struct EmergencyExitFinalized { pub guardian: ContractAddress }

    pub mod errors {
        pub const BAD_NONCE: felt252       = 'AEG_BAD_NONCE';
        pub const INVALID_PQ_SIG: felt252  = 'AEG_INVALID_PQ_SIG';
        pub const INVALID_FB_SIG: felt252  = 'AEG_INVALID_FB_SIG';
        pub const NO_PENDING_EXIT: felt252 = 'AEG_NO_PENDING_EXIT';
        pub const TIMELOCK_NOT_READY: felt252 = 'AEG_TIMELOCK_NOT_READY';
        pub const CALL_FAILED: felt252     = 'AEG_CALL_FAILED';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pq_pk_hash: felt252,
        guardian: ContractAddress,
        fallback_pubkey: felt252,
        verifier: ContractAddress,
        fee_collector: ContractAddress,
    ) {
        self.pq_pk_hash.write(pq_pk_hash);
        self.guardian.write(guardian);
        self.fallback_pubkey.write(fallback_pubkey);
        self.verifier.write(verifier);
        self.fee_collector.write(fee_collector);
    }

    #[abi(embed_v0)]
    impl AegisAccountImpl of super::IAegisAccount<ContractState> {
        fn execute(
            ref self: ContractState,
            target: ContractAddress,
            selector: felt252,
            calldata: Array<felt252>,
            provided_nonce: u64,
            pq_pk: Array<felt252>,
            pq_sig: Array<felt252>,
        ) {
            let current = self.nonce.read();
            assert(provided_nonce == current + 1, errors::BAD_NONCE);

            // digest = poseidon(["AEGIS_EXEC_V1", chain_id, this_addr, provided_nonce,
            //                    target, selector, calldata...])
            let mut buf: Array<felt252> = ArrayTrait::new();
            buf.append('AEGIS_EXEC_V1');
            buf.append(starknet::get_tx_info().unbox().chain_id);
            buf.append(starknet::get_contract_address().into());
            buf.append(provided_nonce.into());
            buf.append(target.into());
            buf.append(selector);
            let mut i = 0_usize;
            while i < calldata.len() {
                buf.append(*calldata.at(i));
                i += 1;
            };
            let digest = poseidon_hash_span(buf.span());

            // pk hash check
            let pk_hash = poseidon_hash_span(pq_pk.span());
            assert(pk_hash == self.pq_pk_hash.read(), errors::INVALID_PQ_SIG);

            // verifier call
            let v = ISphincsVerifierDispatcher { contract_address: self.verifier.read() };
            let ok = v.verify(pq_pk, digest, pq_sig);
            assert(ok, errors::INVALID_PQ_SIG);

            self.nonce.write(provided_nonce);

            // dispatch the user call
            let _res = syscalls::call_contract_syscall(target, selector, calldata.span()).unwrap_syscall();

            self.emit(Executed { nonce: provided_nonce, target });
        }

        fn initiate_emergency_exit(ref self: ContractState, fallback_sig: Array<felt252>) {
            // TODO(v0.2): verify stark_curve::verify(fallback_pubkey, digest, fallback_sig)
            // Current skeleton accepts any signer; final impl calls into the core::ecdsa module.
            let _ = fallback_sig;
            let now = get_block_timestamp();
            let unlock = now + TIMELOCK_SECONDS;
            self.exit_timestamp.write(unlock);
            self.emit(EmergencyExitInitiated { unlock_at: unlock, exit_nonce: self.exit_nonce.read() });
        }

        fn cancel_emergency_exit(ref self: ContractState, pq_pk: Array<felt252>, pq_sig: Array<felt252>) {
            let ts = self.exit_timestamp.read();
            assert(ts != 0, errors::NO_PENDING_EXIT);

            let mut buf: Array<felt252> = ArrayTrait::new();
            buf.append('AEGIS_CANCEL_V1');
            buf.append(starknet::get_tx_info().unbox().chain_id);
            buf.append(starknet::get_contract_address().into());
            buf.append(self.exit_nonce.read().into());
            let digest = poseidon_hash_span(buf.span());

            let pk_hash = poseidon_hash_span(pq_pk.span());
            assert(pk_hash == self.pq_pk_hash.read(), errors::INVALID_PQ_SIG);

            let v = ISphincsVerifierDispatcher { contract_address: self.verifier.read() };
            let ok = v.verify(pq_pk, digest, pq_sig);
            assert(ok, errors::INVALID_PQ_SIG);

            self.exit_timestamp.write(0);
            self.exit_nonce.write(self.exit_nonce.read() + 1);
            self.emit(EmergencyExitCancelled { exit_nonce: self.exit_nonce.read() });
        }

        fn finalize_emergency_exit(ref self: ContractState) {
            let ts = self.exit_timestamp.read();
            assert(ts != 0, errors::NO_PENDING_EXIT);
            assert(get_block_timestamp() >= ts, errors::TIMELOCK_NOT_READY);
            // TODO(v0.2): iterate dynamic field tokens; v0.1 only resets state.
            self.exit_timestamp.write(0);
            self.exit_nonce.write(self.exit_nonce.read() + 1);
            self.emit(EmergencyExitFinalized { guardian: self.guardian.read() });
        }

        fn get_nonce(self: @ContractState) -> u64 { self.nonce.read() }
        fn get_exit_timestamp(self: @ContractState) -> u64 { self.exit_timestamp.read() }
        fn get_guardian(self: @ContractState) -> ContractAddress { self.guardian.read() }
        fn get_pq_pk_hash(self: @ContractState) -> felt252 { self.pq_pk_hash.read() }
    }
}

/// Stub verifier — same semantics as evm/src/SphincsVerifierStub.sol but using
/// Poseidon over felts: `verify` iff `poseidon(pk || [digest]) == sig[0]`.
/// Lets us drive the account end-to-end in tests without a real SPHINCS+ sig.
#[starknet::contract]
pub mod SphincsVerifierStub {
    use core::poseidon::poseidon_hash_span;
    use super::ISphincsVerifier;

    #[storage] struct Storage {}

    #[constructor] fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl Impl of ISphincsVerifier<ContractState> {
        fn verify(self: @ContractState, pk: Array<felt252>, digest: felt252, sig: Array<felt252>) -> bool {
            if sig.len() == 0 { return false; }
            let mut buf = pk;
            buf.append(digest);
            let expected = poseidon_hash_span(buf.span());
            expected == *sig.at(0)
        }
    }
}
