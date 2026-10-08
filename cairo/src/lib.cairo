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

    /// ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pad(16).
    /// Returns the first four big-endian words; words 4..7 are always zero.
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
    fn chain_step(a0: u32, a1: u32, a2: u32, a3: u32, x: Span<u32>) -> [u32; 8] {
        let mut input: Array<u32> = array![a0, a1, a2, a3, 0, 0, 0, 0];
        for w in x {
            input.append(*w);
        };
        compute_sha256_u32_array(input, 0, 0)
    }

    /// T_node(ADRS, l, r) = sha256(ADRS ‖ l ‖ r), 96-byte input.
    fn node_hash(a0: u32, a1: u32, a2: u32, a3: u32, left: Span<u32>, right: Span<u32>) -> [u32; 8] {
        let mut input: Array<u32> = array![a0, a1, a2, a3, 0, 0, 0, 0];
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
    pub fn wots_leaf(layer: u32, tree_idx: u64, leaf_idx: u32, m: u256, wots: Span<u256>) -> [u32; 8] {
        assert(wots.len() == LEN, 'CCHS_WOTS_LEN');
        let d = digits(m);
        let (la0, la1, la2, la3) = adrs_words(layer, tree_idx, TYPE_LEAF, leaf_idx, 0, 0);
        let mut buf: Array<u32> = array![la0, la1, la2, la3, 0, 0, 0, 0];
        let mut c: u32 = 0;
        while c < LEN {
            let start_words = u256_to_words(*wots.at(c));
            let mut x: Span<u32> = start_words.span();
            let mut s: u32 = *d.at(c);
            while s < W - 1 {
                let (a0, a1, a2, a3) = adrs_words(layer, tree_idx, TYPE_CHAIN, leaf_idx, c, s);
                let h = chain_step(a0, a1, a2, a3, x);
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
    /// from a WOTS+ signature on `m` at `leaf_idx` and its authentication path.
    pub fn verify_layer(
        layer: u32,
        tree_idx: u64,
        leaf_idx: u32,
        height: u32,
        m: u256,
        wots: Span<u256>,
        auth: Span<u256>,
    ) -> u256 {
        assert(auth.len() == height, 'CCHS_AUTH_LEN');
        let leaf = wots_leaf(layer, tree_idx, leaf_idx, m, wots);
        let mut node: Span<u32> = leaf.span();
        let mut pos: u32 = leaf_idx;
        let mut k: u32 = 0;
        while k < height {
            let (a0, a1, a2, a3) = adrs_words(layer, tree_idx, TYPE_NODE, pos / 2, k, 0);
            let sib_words = u256_to_words(*auth.at(k));
            let sib: Span<u32> = sib_words.span();
            let h = if pos % 2 == 0 {
                node_hash(a0, a1, a2, a3, node, sib)
            } else {
                node_hash(a0, a1, a2, a3, sib, node)
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
    /// Execute `calls` authorized by a CCHS signature on the next leaf.
    /// `l1_wots` / `l1_auth` may be empty when the subtree root is already cached.
    fn execute(
        ref self: TState,
        calls: Array<Call>,
        l0_wots: Array<u256>,
        l0_auth: Array<u256>,
        l1_wots: Array<u256>,
        l1_auth: Array<u256>,
    ) -> Array<Span<felt252>>;

    /// Rotate `root` and `rec_root`, authorized by the recovery tree.
    fn recover(
        ref self: TState, new_root: u256, new_rec_root: u256, wots: Array<u256>, auth: Array<u256>,
    );

    /// Digest the client must sign for the next `execute` of `calls`.
    fn next_digest(self: @TState, calls: Array<Call>) -> u256;
    /// Digest the client must sign for the next `recover`.
    fn next_recovery_digest(self: @TState, new_root: u256, new_rec_root: u256) -> u256;
    /// Whether the next `execute` must include the top-layer proof.
    fn needs_top_layer(self: @TState) -> bool;

    fn get_root(self: @TState) -> u256;
    fn get_rec_root(self: @TState) -> u256;
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

    #[storage]
    struct Storage {
        /// Top-layer tree root. Rotatable only via `recover`.
        root: u256,
        /// Recovery tree root (single layer, height 8).
        rec_root: u256,
        /// Increments on every recovery; namespaces `cached_root`.
        epoch: u64,
        /// Next unused leaf index in [0, 2^20).
        next_idx: u64,
        /// Transaction nonce bound into every message digest.
        nonce: u64,
        /// Next unused recovery leaf in [0, 256).
        rec_nonce: u64,
        /// (epoch, bottom tree index) -> verified bottom subtree root.
        cached_root: Map<(u64, u64), u256>,
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
    }

    pub mod errors {
        pub const ZERO_ROOT: felt252 = 'CCHS_ZERO_ROOT';
        pub const EXHAUSTED: felt252 = 'CCHS_EXHAUSTED';
        pub const BAD_SUBTREE_ROOT: felt252 = 'CCHS_BAD_SUBTREE_ROOT';
        pub const MISSING_TOP_LAYER: felt252 = 'CCHS_MISSING_TOP_LAYER';
        pub const BAD_TOP_ROOT: felt252 = 'CCHS_BAD_TOP_ROOT';
        pub const BAD_RECOVERY: felt252 = 'CCHS_BAD_RECOVERY';
    }

    #[constructor]
    fn constructor(ref self: ContractState, root: u256, rec_root: u256) {
        assert(root != 0 && rec_root != 0, errors::ZERO_ROOT);
        self.root.write(root);
        self.rec_root.write(rec_root);
    }

    #[abi(embed_v0)]
    impl AegisCCHSImpl of super::IAegisCCHS<ContractState> {
        fn execute(
            ref self: ContractState,
            calls: Array<Call>,
            l0_wots: Array<u256>,
            l0_auth: Array<u256>,
            l1_wots: Array<u256>,
            l1_auth: Array<u256>,
        ) -> Array<Span<felt252>> {
            let idx = self.next_idx.read();
            assert(idx < cchs::CAPACITY, errors::EXHAUSTED);

            let m = self.execute_digest(idx, calls.span());
            self
                .verify_and_cache(
                    idx, m, l0_wots.span(), l0_auth.span(), l1_wots.span(), l1_auth.span(),
                );

            // Effects before interaction.
            self.next_idx.write(idx + 1);
            self.nonce.write(self.nonce.read() + 1);

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
            wots: Array<u256>,
            auth: Array<u256>,
        ) {
            assert(new_root != 0 && new_rec_root != 0, errors::ZERO_ROOT);
            let rn = self.rec_nonce.read();
            assert(rn < cchs::REC_CAPACITY, errors::EXHAUSTED);

            let m = self.recovery_digest(rn, new_root, new_rec_root);
            let leaf_idx: u32 = rn.try_into().unwrap();
            let r = cchs::verify_layer(
                cchs::LAYER_RECOVERY, 0, leaf_idx, cchs::REC_H, m, wots.span(), auth.span(),
            );
            assert(r == self.rec_root.read(), errors::BAD_RECOVERY);

            let new_epoch = self.epoch.read() + 1;
            self.root.write(new_root);
            self.rec_root.write(new_rec_root);
            self.next_idx.write(0);
            self.epoch.write(new_epoch);
            self.rec_nonce.write(rn + 1);
            self.emit(Recovered { new_epoch, new_root, new_rec_root });
        }

        fn next_digest(self: @ContractState, calls: Array<Call>) -> u256 {
            self.execute_digest(self.next_idx.read(), calls.span())
        }

        fn next_recovery_digest(self: @ContractState, new_root: u256, new_rec_root: u256) -> u256 {
            self.recovery_digest(self.rec_nonce.read(), new_root, new_rec_root)
        }

        fn needs_top_layer(self: @ContractState) -> bool {
            let tree_idx = self.next_idx.read() / cchs::LEAVES;
            self.cached_root.read((self.epoch.read(), tree_idx)) == 0
        }

        fn get_root(self: @ContractState) -> u256 {
            self.root.read()
        }
        fn get_rec_root(self: @ContractState) -> u256 {
            self.rec_root.read()
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
    impl InternalImpl of InternalTrait {
        /// Layer-0 verification, then either cache equality or full top-layer
        /// verification with cache write. Panics on any mismatch.
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
            let r0 = cchs::verify_layer(0, tree_idx, leaf_idx, cchs::H, m, l0_wots, l0_auth);

            let epoch = self.epoch.read();
            let cached = self.cached_root.read((epoch, tree_idx));
            if cached != 0 {
                assert(cached == r0, errors::BAD_SUBTREE_ROOT);
                return;
            }
            assert(l1_wots.len() == cchs::LEN, errors::MISSING_TOP_LAYER);
            // Top layer: tree 0, leaf = tree_idx, message = r0.
            let top_leaf: u32 = tree_idx.try_into().unwrap();
            let r1 = cchs::verify_layer(1, 0, top_leaf, cchs::H, r0, l1_wots, l1_auth);
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

        /// M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "starknet" ‖ this(32) ‖ recNonce(8) ‖ newRoot(32) ‖ newRecRoot(32))
        fn recovery_digest(
            self: @ContractState, rec_nonce: u64, new_root: u256, new_rec_root: u256,
        ) -> u256 {
            let mut ba: ByteArray = "";
            ba.append_word('AEGIS_CCHS_RECOVER_V1', 21);
            ba.append_word('starknet', 8);
            let this: felt252 = get_contract_address().into();
            append_felt_be(ref ba, this);
            ba.append_word(rec_nonce.into(), 8);
            append_u256_be(ref ba, new_root);
            append_u256_be(ref ba, new_rec_root);
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
            0, 0, 1, cchs::H, v::OP1_DIGEST, v::op1_l0_wots().span(), v::op1_l0_auth().span(),
        );
        assert(r0 == v::BOTTOM_ROOT_0, 'bottom root mismatch');
    }

    /// ops[0] top layer: layer 1, tree 0, leaf 0, message = bottomRoot0 -> root.
    #[test]
    fn verify_layer_top_fixture() {
        let r1 = cchs::verify_layer(
            1, 0, 0, cchs::H, v::BOTTOM_ROOT_0, v::op0_l1_wots().span(), v::op0_l1_auth().span(),
        );
        assert(r1 == v::ROOT, 'top root mismatch');
    }

    /// recovery: layer 0xff, tree 0, leaf 0, height 8 -> recRoot.
    #[test]
    fn verify_layer_recovery_fixture() {
        let r = cchs::verify_layer(
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
            0, 0, 1, cchs::H, v::OP1_DIGEST, tampered.span(), v::op1_l0_auth().span(),
        );
        assert(r0 != v::BOTTOM_ROOT_0, 'tamper accepted');
    }
}
