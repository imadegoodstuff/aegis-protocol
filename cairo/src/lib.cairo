// SPDX-License-Identifier: MIT
//
// Aegis CCHS — Chain-Cached Hypertree Signature account for Starknet (Cairo 1).
//
// Parameter set CCHS-S-20: WOTS+ (SHA-256, w = 16, 67 chains) under a two-layer
// hypertree of height 10 + 10 (2^20 signatures) plus a single-layer recovery
// tree of height 8. Byte layout of every hash input is identical to
// `evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`; the shared ground truth
// is `evm/test/fixtures/cchs-s-20.json` (see the `tests` module below).
//
// Spec: ../../CCHS.spec.md
//
// Layout of this file:
//   - `cchs`      pure verifier library (ADRS, digits, chain, leaf, Merkle path)
//   - `IAegisCCHS` external interface
//   - `AegisCCHS` the account contract (storage, digest, execute, recover)
//   - `tests`     fixture-driven unit tests (`scarb test`)

/// Pure CCHS-S-20 verifier. No storage, no syscalls other than the SHA-256
/// process-block syscall used by `core::sha256`.
///
/// All 32-byte values cross the API boundary as `u256` (big-endian numeric
/// value of the 32 bytes). Internally they are handled as eight big-endian
/// `u32` words, which is the native input format of
/// `core::sha256::compute_sha256_u32_array`; every hash input in this scheme
/// (64, 96 and 2176 bytes) is a multiple of 4 bytes, so no partial last word
/// is ever needed.
pub mod cchs {
    use core::sha256::compute_sha256_u32_array;

    /// Winternitz parameter.
    pub const W: u32 = 16;
    /// Number of WOTS+ chains: 64 message digits + 3 checksum digits.
    pub const LEN: u32 = 67;
    /// Height of each hypertree layer.
    pub const H: u32 = 10;
    /// Height of the recovery tree.
    pub const REC_H: u32 = 8;
    /// Leaves per layer tree (2^H).
    pub const LEAVES: u64 = 1024;
    /// Total signatures per key (2^(2H)).
    pub const CAPACITY: u64 = 1048576;
    /// Recovery signatures per key (2^REC_H).
    pub const REC_CAPACITY: u64 = 256;

    /// ADRS type bytes.
    pub const TYPE_CHAIN: u32 = 0;
    pub const TYPE_LEAF: u32 = 1;
    pub const TYPE_NODE: u32 = 2;
    /// Layer id of the recovery tree.
    pub const LAYER_RECOVERY: u32 = 0xFF;

    // ------------------------------------------------------------ conversions

    /// Appends the four big-endian 32-bit words of a `u128`.
    fn append_u128_words(ref out: Array<u32>, v: u128) {
        let w0: u32 = (v / 0x1000000000000000000000000_u128).try_into().unwrap();
        let w1: u32 = ((v / 0x10000000000000000_u128) % 0x100000000_u128).try_into().unwrap();
        let w2: u32 = ((v / 0x100000000_u128) % 0x100000000_u128).try_into().unwrap();
        let w3: u32 = (v % 0x100000000_u128).try_into().unwrap();
        out.append(w0);
        out.append(w1);
        out.append(w2);
        out.append(w3);
    }

    /// 32-byte value as eight big-endian `u32` words (word 0 = most significant).
    pub fn u256_to_words(x: u256) -> Array<u32> {
        let mut out: Array<u32> = array![];
        append_u128_words(ref out, x.high);
        append_u128_words(ref out, x.low);
        out
    }

    /// Eight big-endian `u32` words back to a `u256`.
    pub fn words_to_u256(w: Span<u32>) -> u256 {
        let mut value: u256 = 0;
        for word in w {
            value = value * 0x100000000;
            value = value + (*word).into();
        };
        value
    }

    // ------------------------------------------------------------------ ADRS

    /// ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16).
    /// Returns the first four big-endian words; words 4..7 are the public
    /// seed of the key tree (`seed_words`).
    pub fn adrs_words(
        layer: u32, tree_idx: u64, typ: u32, leaf_idx: u32, chain_idx: u32, step: u32,
    ) -> (u32, u32, u32, u32) {
        // treeIdx bits 63..40 (24 bits), 39..8 (32 bits), 7..0 (8 bits).
        let t_hi: u32 = (tree_idx / 0x10000000000_u64).try_into().unwrap();
        let t_mid: u32 = ((tree_idx / 0x100_u64) % 0x100000000_u64).try_into().unwrap();
        let t_lo: u32 = (tree_idx % 0x100_u64).try_into().unwrap();
        // bytes 0..3  : layer ‖ treeIdx[0..3]
        let w0: u32 = layer * 0x1000000 + t_hi;
        // bytes 4..7  : treeIdx[3..7]
        let w1: u32 = t_mid;
        // bytes 8..11 : treeIdx[7] ‖ type ‖ leafIdx[0..2]
        let w2: u32 = t_lo * 0x1000000 + typ * 0x10000 + leaf_idx / 0x10000;
        // bytes 12..15: leafIdx[2..4] ‖ chainIdx ‖ step
        let w3: u32 = (leaf_idx % 0x10000) * 0x10000 + chain_idx * 0x100 + step;
        (w0, w1, w2, w3)
    }

    /// The 16-byte public seed (big-endian numeric value) as ADRS words 4..7.
    pub fn seed_words(seed: u128) -> Array<u32> {
        let mut out: Array<u32> = array![];
        append_u128_words(ref out, seed);
        out
    }

    /// First four ADRS words followed by the seed words.
    fn adrs_full(a0: u32, a1: u32, a2: u32, a3: u32, seed: Span<u32>) -> Array<u32> {
        let mut out: Array<u32> = array![a0, a1, a2, a3];
        for w in seed {
            out.append(*w);
        };
        out
    }

    // ---------------------------------------------------------------- digits

    /// 64 base-16 message digits (high nibble first) followed by 3 base-16
    /// checksum digits (big-endian). Matches Solidity `_digits` / TS `digits`.
    pub fn digits(m: u256) -> Array<u32> {
        let words = u256_to_words(m);
        let mut d: Array<u32> = array![];
        let mut csum: u32 = 0;
        for w in words.span() {
            // Eight nibbles per word, most significant first.
            let mut div: u32 = 0x10000000;
            loop {
                let digit: u32 = (*w / div) % 16;
                d.append(digit);
                csum += 15 - digit;
                if div == 1 {
                    break;
                }
                div = div / 16;
            };
        };
        // csum <= 64 * 15 = 960 < 16^3.
        d.append((csum / 256) % 16);
        d.append((csum / 16) % 16);
        d.append(csum % 16);
        d
    }

    // ---------------------------------------------------------------- hashing

    /// F(ADRS, x) = sha256(ADRS ‖ x), 64-byte input.
    fn chain_step(a0: u32, a1: u32, a2: u32, a3: u32, seed: Span<u32>, x: Span<u32>) -> [u32; 8] {
        let mut input: Array<u32> = adrs_full(a0, a1, a2, a3, seed);
        for w in x {
            input.append(*w);
        };
        compute_sha256_u32_array(input, 0, 0)
    }

    /// T_node(ADRS, l, r) = sha256(ADRS ‖ l ‖ r), 96-byte input.
    fn node_hash(
        a0: u32, a1: u32, a2: u32, a3: u32, seed: Span<u32>, left: Span<u32>, right: Span<u32>,
    ) -> [u32; 8] {
        let mut input: Array<u32> = adrs_full(a0, a1, a2, a3, seed);
        for w in left {
            input.append(*w);
        };
        for w in right {
            input.append(*w);
        };
        compute_sha256_u32_array(input, 0, 0)
    }

    /// From a WOTS+ signature on `m`, complete every chain to its end and
    /// compress the 67 chain ends into the leaf:
    /// leaf = sha256(ADRS_leaf ‖ pk_0 ‖ … ‖ pk_66), 2176-byte input.
    pub fn wots_leaf(
        seed: Span<u32>, layer: u32, tree_idx: u64, leaf_idx: u32, m: u256, wots: Span<u256>,
    ) -> [u32; 8] {
        assert(wots.len() == LEN, 'CCHS_WOTS_LEN');
        let d = digits(m);
        let (la0, la1, la2, la3) = adrs_words(layer, tree_idx, TYPE_LEAF, leaf_idx, 0, 0);
        let mut buf: Array<u32> = adrs_full(la0, la1, la2, la3, seed);
        let mut c: u32 = 0;
        while c < LEN {
            let start_words = u256_to_words(*wots.at(c));
            let mut x: Span<u32> = start_words.span();
            let mut s: u32 = *d.at(c);
            while s < W - 1 {
                let (a0, a1, a2, a3) = adrs_words(layer, tree_idx, TYPE_CHAIN, leaf_idx, c, s);
                let h = chain_step(a0, a1, a2, a3, seed, x);
                x = h.span();
                s += 1;
            };
            for w in x {
                buf.append(*w);
            };
            c += 1;
        };
        compute_sha256_u32_array(buf, 0, 0)
    }

    /// Recompute the root of tree (`layer`, `tree_idx`) of height `height`
    /// from a WOTS+ signature on `m` at `leaf_idx` and its authentication path,
    /// hashing under the public seed `seed`.
    pub fn verify_layer(
        seed: u128,
        layer: u32,
        tree_idx: u64,
        leaf_idx: u32,
        height: u32,
        m: u256,
        wots: Span<u256>,
        auth: Span<u256>,
    ) -> u256 {
        assert(auth.len() == height, 'CCHS_AUTH_LEN');
        let seed_arr = seed_words(seed);
        let sw: Span<u32> = seed_arr.span();
        let leaf = wots_leaf(sw, layer, tree_idx, leaf_idx, m, wots);
        let mut node: Span<u32> = leaf.span();
        let mut pos: u32 = leaf_idx;
        let mut k: u32 = 0;
        while k < height {
            let (a0, a1, a2, a3) = adrs_words(layer, tree_idx, TYPE_NODE, pos / 2, k, 0);
            let sib_words = u256_to_words(*auth.at(k));
            let sib: Span<u32> = sib_words.span();
            let h = if pos % 2 == 0 {
                node_hash(a0, a1, a2, a3, sw, node, sib)
            } else {
                node_hash(a0, a1, a2, a3, sw, sib, node)
            };
            node = h.span();
            pos = pos / 2;
            k += 1;
        };
        words_to_u256(node)
    }
}

use starknet::account::Call;

#[starknet::interface]
pub trait IAegisCCHS<TState> {
    /// Execute `calls` authorized by a CCHS signature on leaf `idx`.
    ///
    /// `idx` is chosen by the signer and must be `>= next_idx`; on success
    /// `next_idx` becomes `idx + 1`, so every lower leaf is abandoned forever.
    /// `idx` is bound into the digest, so only the key holder can skip.
    /// `l1_wots` / `l1_auth` are required when the subtree of `idx` is not
    /// cached yet and are ignored when it already is.
    fn execute(
        ref self: TState,
        calls: Array<Call>,
        idx: u64,
        l0_wots: Array<u256>,
        l0_auth: Array<u256>,
        l1_wots: Array<u256>,
        l1_auth: Array<u256>,
    ) -> Array<Span<felt252>>;

    /// Rotate the public key (`root`, `rec_root`, `seed`), authorized by the
    /// recovery tree under the current seed.
    fn recover(
        ref self: TState,
        new_root: u256,
        new_rec_root: u256,
        new_seed: u128,
        wots: Array<u256>,
        auth: Array<u256>,
    );

    /// Digest the client must sign for an `execute` of `calls` at leaf `idx`
    /// (`idx >= next_idx`) with the current nonce.
    fn digest_at(self: @TState, idx: u64, calls: Array<Call>) -> u256;
    /// Digest for an `execute` at `next_idx`.
    fn next_digest(self: @TState, calls: Array<Call>) -> u256;
    /// Digest the client must sign for the next `recover`.
    fn next_recovery_digest(
        self: @TState, new_root: u256, new_rec_root: u256, new_seed: u128,
    ) -> u256;
    /// Whether an `execute` at leaf `idx` must include the top-layer proof.
    fn needs_top_layer_at(self: @TState, idx: u64) -> bool;
    /// Whether an `execute` at `next_idx` must include the top-layer proof.
    fn needs_top_layer(self: @TState) -> bool;

    fn get_root(self: @TState) -> u256;
    fn get_rec_root(self: @TState) -> u256;
    /// 16-byte public seed of the current key tree (big-endian numeric value).
    fn get_seed(self: @TState) -> u128;
    fn get_epoch(self: @TState) -> u64;
    fn get_next_idx(self: @TState) -> u64;
    fn get_nonce(self: @TState) -> u64;
    fn get_rec_nonce(self: @TState) -> u64;
    fn get_cached_root(self: @TState, epoch: u64, tree_idx: u64) -> u256;
}

#[starknet::contract]
pub mod AegisCCHS {
    use core::sha256::compute_sha256_byte_array;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::call_contract_syscall;
    use starknet::{SyscallResultTrait, get_contract_address};
    use super::cchs;

    /// Members are crate-visible so the state-machine tests can seed and
    /// inspect the account state directly; external access goes through the
    /// `get_*` views.
    #[storage]
    struct Storage {
        /// Top-layer tree root. Rotatable only via `recover`.
        pub(crate) root: u256,
        /// Recovery tree root (single layer, height 8).
        pub(crate) rec_root: u256,
        /// Public seed of the current key tree (last 16 bytes of every ADRS).
        pub(crate) seed: u128,
        /// Increments on every recovery; namespaces `cached_root`.
        pub(crate) epoch: u64,
        /// Next unused leaf index in [0, 2^20). Advances to `idx + 1` on
        /// every accepted `execute`, so skipped leaves are abandoned.
        pub(crate) next_idx: u64,
        /// Transaction nonce bound into every message digest.
        pub(crate) nonce: u64,
        /// Next unused recovery leaf in [0, 256).
        pub(crate) rec_nonce: u64,
        /// (epoch, bottom tree index) -> verified bottom subtree root.
        pub(crate) cached_root: Map<(u64, u64), u256>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Executed: Executed,
        SubtreeCached: SubtreeCached,
        Recovered: Recovered,
    }

    #[derive(Drop, starknet::Event)]
    struct Executed {
        #[key]
        idx: u64,
        n_calls: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct SubtreeCached {
        #[key]
        epoch: u64,
        #[key]
        tree_idx: u64,
        subtree_root: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Recovered {
        #[key]
        new_epoch: u64,
        new_root: u256,
        new_rec_root: u256,
        new_seed: u128,
    }

    pub mod errors {
        pub const ZERO_ROOT: felt252 = 'CCHS_ZERO_ROOT';
        pub const EXHAUSTED: felt252 = 'CCHS_EXHAUSTED';
        pub const INDEX_USED: felt252 = 'CCHS_INDEX_USED';
        pub const BAD_SUBTREE_ROOT: felt252 = 'CCHS_BAD_SUBTREE_ROOT';
        pub const MISSING_TOP_LAYER: felt252 = 'CCHS_MISSING_TOP_LAYER';
        pub const BAD_TOP_ROOT: felt252 = 'CCHS_BAD_TOP_ROOT';
        pub const BAD_RECOVERY: felt252 = 'CCHS_BAD_RECOVERY';
    }

    #[constructor]
    fn constructor(ref self: ContractState, root: u256, rec_root: u256, seed: u128) {
        assert(root != 0 && rec_root != 0, errors::ZERO_ROOT);
        self.root.write(root);
        self.rec_root.write(rec_root);
        self.seed.write(seed);
    }

    #[abi(embed_v0)]
    impl AegisCCHSImpl of super::IAegisCCHS<ContractState> {
        fn execute(
            ref self: ContractState,
            calls: Array<Call>,
            idx: u64,
            l0_wots: Array<u256>,
            l0_auth: Array<u256>,
            l1_wots: Array<u256>,
            l1_auth: Array<u256>,
        ) -> Array<Span<felt252>> {
            self.check_index(idx);

            let m = self.execute_digest(idx, calls.span());
            self
                .verify_and_cache(
                    idx, m, l0_wots.span(), l0_auth.span(), l1_wots.span(), l1_auth.span(),
                );

            // Effects before interaction.
            self.advance(idx);

            let mut results: Array<Span<felt252>> = array![];
            for call in calls.span() {
                let res = call_contract_syscall(*call.to, *call.selector, *call.calldata)
                    .unwrap_syscall();
                results.append(res);
            };
            self.emit(Executed { idx, n_calls: calls.len() });
            results
        }

        fn recover(
            ref self: ContractState,
            new_root: u256,
            new_rec_root: u256,
            new_seed: u128,
            wots: Array<u256>,
            auth: Array<u256>,
        ) {
            assert(new_root != 0 && new_rec_root != 0, errors::ZERO_ROOT);
            let rn = self.rec_nonce.read();
            assert(rn < cchs::REC_CAPACITY, errors::EXHAUSTED);

            let m = self.recovery_digest(rn, new_root, new_rec_root, new_seed);
            let leaf_idx: u32 = rn.try_into().unwrap();
            // The recovery tree belongs to the current key: verified under the
            // current seed; the new seed only takes effect afterwards.
            let r = cchs::verify_layer(
                self.seed.read(),
                cchs::LAYER_RECOVERY,
                0,
                leaf_idx,
                cchs::REC_H,
                m,
                wots.span(),
                auth.span(),
            );
            assert(r == self.rec_root.read(), errors::BAD_RECOVERY);

            let new_epoch = self.epoch.read() + 1;
            self.root.write(new_root);
            self.rec_root.write(new_rec_root);
            self.seed.write(new_seed);
            self.next_idx.write(0);
            self.epoch.write(new_epoch);
            self.rec_nonce.write(rn + 1);
            self.emit(Recovered { new_epoch, new_root, new_rec_root, new_seed });
        }

        fn digest_at(self: @ContractState, idx: u64, calls: Array<Call>) -> u256 {
            self.execute_digest(idx, calls.span())
        }

        fn next_digest(self: @ContractState, calls: Array<Call>) -> u256 {
            self.execute_digest(self.next_idx.read(), calls.span())
        }

        fn next_recovery_digest(
            self: @ContractState, new_root: u256, new_rec_root: u256, new_seed: u128,
        ) -> u256 {
            self.recovery_digest(self.rec_nonce.read(), new_root, new_rec_root, new_seed)
        }

        fn needs_top_layer_at(self: @ContractState, idx: u64) -> bool {
            let tree_idx = idx / cchs::LEAVES;
            self.cached_root.read((self.epoch.read(), tree_idx)) == 0
        }

        fn needs_top_layer(self: @ContractState) -> bool {
            self.needs_top_layer_at(self.next_idx.read())
        }

        fn get_root(self: @ContractState) -> u256 {
            self.root.read()
        }
        fn get_rec_root(self: @ContractState) -> u256 {
            self.rec_root.read()
        }
        fn get_seed(self: @ContractState) -> u128 {
            self.seed.read()
        }
        fn get_epoch(self: @ContractState) -> u64 {
            self.epoch.read()
        }
        fn get_next_idx(self: @ContractState) -> u64 {
            self.next_idx.read()
        }
        fn get_nonce(self: @ContractState) -> u64 {
            self.nonce.read()
        }
        fn get_rec_nonce(self: @ContractState) -> u64 {
            self.rec_nonce.read()
        }
        fn get_cached_root(self: @ContractState, epoch: u64, tree_idx: u64) -> u256 {
            self.cached_root.read((epoch, tree_idx))
        }
    }

    #[generate_trait]
    pub impl InternalImpl of InternalTrait {
        /// Index discipline: `idx` must not be behind `next_idx` (a used or
        /// abandoned leaf) and must lie inside the 2^20 index space.
        fn check_index(self: @ContractState, idx: u64) {
            assert(idx >= self.next_idx.read(), errors::INDEX_USED);
            assert(idx < cchs::CAPACITY, errors::EXHAUSTED);
        }

        /// State update after a verified signature at `idx`: every leaf up to
        /// and including `idx` is consumed, and the nonce moves on.
        fn advance(ref self: ContractState, idx: u64) {
            self.next_idx.write(idx + 1);
            self.nonce.write(self.nonce.read() + 1);
        }

        /// Layer-0 verification, then either cache equality or full top-layer
        /// verification with cache write. Panics on any mismatch. When the
        /// subtree is already cached, a supplied top layer is ignored rather
        /// than rejected, so a transaction prepared before another
        /// registration landed still succeeds.
        fn verify_and_cache(
            ref self: ContractState,
            idx: u64,
            m: u256,
            l0_wots: Span<u256>,
            l0_auth: Span<u256>,
            l1_wots: Span<u256>,
            l1_auth: Span<u256>,
        ) {
            let tree_idx: u64 = idx / cchs::LEAVES;
            let leaf_idx: u32 = (idx % cchs::LEAVES).try_into().unwrap();
            let seed = self.seed.read();
            let r0 = cchs::verify_layer(seed, 0, tree_idx, leaf_idx, cchs::H, m, l0_wots, l0_auth);

            let epoch = self.epoch.read();
            let cached = self.cached_root.read((epoch, tree_idx));
            if cached != 0 {
                assert(cached == r0, errors::BAD_SUBTREE_ROOT);
                return;
            }
            assert(l1_wots.len() == cchs::LEN, errors::MISSING_TOP_LAYER);
            // Top layer: tree 0, leaf = tree_idx, message = r0.
            let top_leaf: u32 = tree_idx.try_into().unwrap();
            let r1 = cchs::verify_layer(seed, 1, 0, top_leaf, cchs::H, r0, l1_wots, l1_auth);
            assert(r1 == self.root.read(), errors::BAD_TOP_ROOT);
            self.cached_root.write((epoch, tree_idx), r0);
            self.emit(SubtreeCached { epoch, tree_idx, subtree_root: r0 });
        }

        /// M = sha256("AEGIS_CCHS_V1" ‖ "starknet" ‖ this(32) ‖ nonce(8) ‖ idx(8) ‖ calls_hash(32))
        /// calls_hash = sha256(for each call: to(32) ‖ selector(32) ‖ calldata_len(4) ‖ calldata[i](32)…)
        fn execute_digest(self: @ContractState, idx: u64, calls: Span<Call>) -> u256 {
            let mut body: ByteArray = "";
            for call in calls {
                let to: felt252 = (*call.to).into();
                append_felt_be(ref body, to);
                append_felt_be(ref body, *call.selector);
                let calldata: Span<felt252> = *call.calldata;
                body.append_word(calldata.len().into(), 4);
                for x in calldata {
                    append_felt_be(ref body, *x);
                };
            };
            let calls_hash = cchs::words_to_u256(compute_sha256_byte_array(@body).span());

            let mut ba: ByteArray = "";
            ba.append_word('AEGIS_CCHS_V1', 13);
            ba.append_word('starknet', 8);
            let this: felt252 = get_contract_address().into();
            append_felt_be(ref ba, this);
            ba.append_word(self.nonce.read().into(), 8);
            ba.append_word(idx.into(), 8);
            append_u256_be(ref ba, calls_hash);
            cchs::words_to_u256(compute_sha256_byte_array(@ba).span())
        }

        /// M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "starknet" ‖ this(32) ‖ recNonce(8)
        ///                ‖ newRoot(32) ‖ newRecRoot(32) ‖ newSeed(16))
        fn recovery_digest(
            self: @ContractState, rec_nonce: u64, new_root: u256, new_rec_root: u256, new_seed: u128,
        ) -> u256 {
            let mut ba: ByteArray = "";
            ba.append_word('AEGIS_CCHS_RECOVER_V1', 21);
            ba.append_word('starknet', 8);
            let this: felt252 = get_contract_address().into();
            append_felt_be(ref ba, this);
            ba.append_word(rec_nonce.into(), 8);
            append_u256_be(ref ba, new_root);
            append_u256_be(ref ba, new_rec_root);
            ba.append_word(new_seed.into(), 16);
            cchs::words_to_u256(compute_sha256_byte_array(@ba).span())
        }
    }

    /// Appends a `u256` as 32 big-endian bytes.
    fn append_u256_be(ref ba: ByteArray, x: u256) {
        ba.append_word(x.high.into(), 16);
        ba.append_word(x.low.into(), 16);
    }

    /// Appends a `felt252` as 32 big-endian bytes (numeric value, zero-padded).
    fn append_felt_be(ref ba: ByteArray, x: felt252) {
        let v: u256 = x.into();
        append_u256_be(ref ba, v);
    }
}

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod tests {
    use super::cchs;
    use super::test_vectors::vectors as v;

    #[test]
    fn digits_of_fixture_digest() {
        // 0x7c06…cede: nibbles 7, c, 0, 6 … d, e; checksum 430 = 0x1ae.
        let d = cchs::digits(v::OP1_DIGEST);
        assert(d.len() == 67, 'len');
        assert(*d.at(0) == 7, 'd0');
        assert(*d.at(1) == 12, 'd1');
        assert(*d.at(2) == 0, 'd2');
        assert(*d.at(3) == 6, 'd3');
        assert(*d.at(62) == 13, 'd62');
        assert(*d.at(63) == 14, 'd63');
        assert(*d.at(64) == 1, 'c0');
        assert(*d.at(65) == 10, 'c1');
        assert(*d.at(66) == 14, 'c2');
    }

    #[test]
    fn digits_all_zero_message() {
        // 64 zero digits -> csum = 960 = 0x3c0.
        let d = cchs::digits(0);
        assert(*d.at(0) == 0, 'd0');
        assert(*d.at(63) == 0, 'd63');
        assert(*d.at(64) == 3, 'c0');
        assert(*d.at(65) == 12, 'c1');
        assert(*d.at(66) == 0, 'c2');
    }

    #[test]
    fn adrs_layout() {
        // layer 0xff, treeIdx 0x0102030405060708, type 2, leafIdx 0x0a0b0c0d, chain 0x11, step 0x0e
        let (w0, w1, w2, w3) = cchs::adrs_words(0xff, 0x0102030405060708, 2, 0x0a0b0c0d, 0x11, 0x0e);
        assert(w0 == 0xff010203, 'w0');
        assert(w1 == 0x04050607, 'w1');
        assert(w2 == 0x08020a0b, 'w2');
        assert(w3 == 0x0c0d110e, 'w3');
        // Seed words: 16 bytes big-endian as ADRS words 4..7.
        let s = cchs::seed_words(0x0102030405060708090a0b0c0d0e0f10_u128);
        assert(*s.at(0) == 0x01020304, 's0');
        assert(*s.at(1) == 0x05060708, 's1');
        assert(*s.at(2) == 0x090a0b0c, 's2');
        assert(*s.at(3) == 0x0d0e0f10, 's3');
    }

    #[test]
    fn u256_words_roundtrip() {
        let x: u256 = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20_u256;
        let w = cchs::u256_to_words(x);
        assert(*w.at(0) == 0x01020304, 'w0');
        assert(*w.at(3) == 0x0d0e0f10, 'w3');
        assert(*w.at(4) == 0x11121314, 'w4');
        assert(*w.at(7) == 0x1d1e1f20, 'w7');
        assert(cchs::words_to_u256(w.span()) == x, 'roundtrip');
    }

    /// ops[1] (cached path): layer 0, tree 0, leaf 1 -> bottomRoot0.
    #[test]
    fn verify_layer_bottom_fixture() {
        let r0 = cchs::verify_layer(
            v::SEED, 0, 0, 1, cchs::H, v::OP1_DIGEST, v::op1_l0_wots().span(), v::op1_l0_auth().span(),
        );
        assert(r0 == v::BOTTOM_ROOT_0, 'bottom root mismatch');
    }

    /// The same signature hashed under a different public seed reaches a
    /// different root: the seed separates every tree's hash functions.
    #[test]
    fn verify_layer_rejects_wrong_seed() {
        let r0 = cchs::verify_layer(
            v::SEED + 1, 0, 0, 1, cchs::H, v::OP1_DIGEST, v::op1_l0_wots().span(), v::op1_l0_auth().span(),
        );
        assert(r0 != v::BOTTOM_ROOT_0, 'seed ignored');
    }

    /// ops[0] top layer: layer 1, tree 0, leaf 0, message = bottomRoot0 -> root.
    #[test]
    fn verify_layer_top_fixture() {
        let r1 = cchs::verify_layer(
            v::SEED, 1, 0, 0, cchs::H, v::BOTTOM_ROOT_0, v::op0_l1_wots().span(), v::op0_l1_auth().span(),
        );
        assert(r1 == v::ROOT, 'top root mismatch');
    }

    /// recovery: layer 0xff, tree 0, leaf 0, height 8 -> recRoot.
    #[test]
    fn verify_layer_recovery_fixture() {
        let r = cchs::verify_layer(
            v::SEED,
            cchs::LAYER_RECOVERY,
            0,
            0,
            cchs::REC_H,
            v::REC_DIGEST,
            v::rec_wots().span(),
            v::rec_auth().span(),
        );
        assert(r == v::REC_ROOT, 'rec root mismatch');
    }

    /// A tampered chain value must change the root.
    #[test]
    fn verify_layer_rejects_tampered_chain() {
        let mut wots = v::op1_l0_wots();
        let first = wots.pop_front().unwrap();
        let mut tampered: Array<u256> = array![first + 1];
        for x in wots.span() {
            tampered.append(*x);
        };
        let r0 = cchs::verify_layer(
            v::SEED, 0, 0, 1, cchs::H, v::OP1_DIGEST, tampered.span(), v::op1_l0_auth().span(),
        );
        assert(r0 != v::BOTTOM_ROOT_0, 'tamper accepted');
    }

    // ------------------------------------------------- signer-chosen index
    //
    // State-machine tests run against the contract state in the test runner
    // (`contract_state_for_testing`) and call the internal steps of `execute`
    // directly: `check_index`, `verify_and_cache`, `advance`. The fixture
    // digests are passed as the message, which keeps the vectors byte-exact
    // with the other adapters even though the Starknet digest format differs.
    // Subtree 0 is registered by writing `cached_root` directly instead of
    // verifying `ops[0]`, so each test runs at most three layer verifications.

    use super::{AegisCCHS, IAegisCCHS};
    use super::AegisCCHS::InternalTrait;
    use starknet::storage::{
        StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };

    /// Account state right after `ops[0]`: subtree 0 cached, next_idx 1, nonce 1.
    fn state_after_op0() -> AegisCCHS::ContractState {
        let mut s = AegisCCHS::contract_state_for_testing();
        s.root.write(v::ROOT);
        s.rec_root.write(v::REC_ROOT);
        s.seed.write(v::SEED);
        s.cached_root.write((0, 0), v::BOTTOM_ROOT_0);
        s.next_idx.write(1);
        s.nonce.write(1);
        s
    }

    fn empty() -> Array<u256> {
        array![]
    }

    /// Skip leaves 1..4 inside the cached subtree (idx 5), then jump to the
    /// first leaf of subtree 1 (idx 1024) with its top layer.
    #[test]
    fn skip_within_subtree_then_across_subtrees() {
        let mut s = state_after_op0();

        s.check_index(5);
        s
            .verify_and_cache(
                5,
                v::OP5_DIGEST,
                v::op5_l0_wots().span(),
                v::op5_l0_auth().span(),
                empty().span(),
                empty().span(),
            );
        s.advance(5);
        assert(s.next_idx.read() == 6, 'next_idx after 5');
        assert(s.nonce.read() == 2, 'nonce after 5');

        assert(s.needs_top_layer_at(1024), 'subtree 1 uncached');
        s.check_index(1024);
        s
            .verify_and_cache(
                1024,
                v::OP1024_DIGEST,
                v::op1024_l0_wots().span(),
                v::op1024_l0_auth().span(),
                v::op1024_l1_wots().span(),
                v::op1024_l1_auth().span(),
            );
        s.advance(1024);
        assert(s.next_idx.read() == 1025, 'next_idx after 1024');
        assert(s.nonce.read() == 3, 'nonce after 1024');
        assert(s.cached_root.read((0, 1)) == v::BOTTOM_ROOT_1, 'bottom root 1');
        assert(!s.needs_top_layer_at(1024), 'subtree 1 cached');
    }

    /// An index behind `next_idx` is rejected before any hashing.
    #[test]
    #[should_panic(expected: ('CCHS_INDEX_USED',))]
    fn index_reuse_rejected() {
        let mut s = state_after_op0();
        s.next_idx.write(6); // after the skip to 5
        s.check_index(1);
    }

    /// The skipped-to leaf itself is consumed as well.
    #[test]
    #[should_panic(expected: ('CCHS_INDEX_USED',))]
    fn index_reuse_of_skipped_leaf_rejected() {
        let mut s = state_after_op0();
        s.next_idx.write(6);
        s.check_index(5);
    }

    /// `idx = next_idx` is always allowed; the index space ends at 2^20.
    #[test]
    fn index_at_next_idx_allowed_and_capacity_bounded() {
        let mut s = state_after_op0();
        s.next_idx.write(6);
        s.check_index(6);
        s.check_index(cchs::CAPACITY - 1);
    }

    #[test]
    #[should_panic(expected: ('CCHS_EXHAUSTED',))]
    fn index_at_capacity_rejected() {
        let s = state_after_op0();
        s.check_index(cchs::CAPACITY);
    }

    /// Jumping into a fresh subtree without its top layer is rejected.
    #[test]
    #[should_panic(expected: ('CCHS_MISSING_TOP_LAYER',))]
    fn jump_to_fresh_subtree_without_top_layer_rejected() {
        let mut s = state_after_op0();
        s.check_index(1024);
        s
            .verify_and_cache(
                1024,
                v::OP1024_DIGEST,
                v::op1024_l0_wots().span(),
                v::op1024_l0_auth().span(),
                empty().span(),
                empty().span(),
            );
    }

    /// A signature for leaf 5 cannot be used at leaf 6: the leaf index enters
    /// every ADRS, so the recomputed bottom root no longer matches the cache.
    #[test]
    #[should_panic(expected: ('CCHS_BAD_SUBTREE_ROOT',))]
    fn signature_bound_to_index() {
        let mut s = state_after_op0();
        s.check_index(6);
        s
            .verify_and_cache(
                6,
                v::OP5_DIGEST,
                v::op5_l0_wots().span(),
                v::op5_l0_auth().span(),
                empty().span(),
                empty().span(),
            );
    }

    /// A top layer supplied for an already registered subtree is ignored, not
    /// rejected: `ops[1]` with `ops[0].l1` attached is accepted.
    #[test]
    fn redundant_top_layer_ignored() {
        let mut s = state_after_op0();
        s.check_index(1);
        s
            .verify_and_cache(
                1,
                v::OP1_DIGEST,
                v::op1_l0_wots().span(),
                v::op1_l0_auth().span(),
                v::op0_l1_wots().span(),
                v::op0_l1_auth().span(),
            );
        s.advance(1);
        assert(s.next_idx.read() == 2, 'next_idx after 1');
        assert(s.cached_root.read((0, 0)) == v::BOTTOM_ROOT_0, 'cache unchanged');
    }
}
