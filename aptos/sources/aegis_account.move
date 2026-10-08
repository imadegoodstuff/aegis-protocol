/// Aegis CCHS account on Aptos (CCHS-S-20).
///
/// Hash-only post-quantum account authorization. Every operation is a WOTS+
/// signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of
/// height 10 + 10 (2^20 signatures). The top-layer proof for each bottom
/// subtree is verified once and cached; later signatures in that subtree
/// carry only the bottom layer.
///
/// Byte-exact with `evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`
/// for ADRS, chain steps, leaf compression and Merkle nodes. Only the
/// message digest differs per chain (see `digest`). Spec: ../../CCHS.spec.md
module aegis::aegis_account {
    use std::bcs;
    use std::error;
    use std::hash;
    use std::signer;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::aptos_account;
    use aptos_framework::event;

    // ------------------------------------------------------------ params
    const LEN: u64 = 67;          // 64 message chains + 3 checksum chains
    const H: u64 = 10;            // tree height per layer
    const REC_H: u64 = 8;         // recovery tree height
    const CAPACITY: u64 = 1048576; // 2^(2*H)
    const REC_CAPACITY: u64 = 256; // 2^REC_H
    const LAYER_REC: u8 = 0xFF;

    // ------------------------------------------------------------ errors
    const E_ALREADY_INIT: u64 = 1;
    const E_NOT_INIT: u64 = 2;
    const E_BAD_LENGTH: u64 = 3;
    const E_EXHAUSTED: u64 = 4;
    const E_BAD_SUBTREE_ROOT: u64 = 5;
    const E_MISSING_TOP_LAYER: u64 = 6;
    const E_BAD_TOP_ROOT: u64 = 7;
    const E_BAD_RECOVERY: u64 = 8;
    const E_ZERO_ROOT: u64 = 9;

    // ------------------------------------------------------------ state
    /// Stored under the owner's address.
    struct CchsAccount has key {
        /// Top-layer tree root. Rotatable only via `recover`.
        root: vector<u8>,
        /// Recovery tree root (single layer, height 8).
        rec_root: vector<u8>,
        /// Increments on every recovery; namespaces `cached_root`.
        epoch: u64,
        /// Next unused leaf index in [0, 2^20).
        next_idx: u64,
        /// Nonce bound into every message digest.
        nonce: u64,
        /// Next unused recovery leaf in [0, 256).
        rec_nonce: u64,
        /// key = (epoch << 64) | bottom_tree_idx  ->  verified bottom subtree root
        cached_root: Table<u128, vector<u8>>,
    }

    // ------------------------------------------------------------ events
    #[event]
    struct Executed has drop, store { account: address, idx: u64, recipient: address, amount: u64 }
    #[event]
    struct SubtreeCached has drop, store { account: address, epoch: u64, tree_idx: u64, subtree_root: vector<u8> }
    #[event]
    struct Recovered has drop, store { account: address, new_epoch: u64, new_root: vector<u8>, new_rec_root: vector<u8> }

    // ============================================================ create

    /// Publish a CCHS account under `account`'s address.
    public entry fun create(account: &signer, root: vector<u8>, rec_root: vector<u8>) {
        let addr = signer::address_of(account);
        assert!(!exists<CchsAccount>(addr), error::already_exists(E_ALREADY_INIT));
        assert_root(&root);
        assert_root(&rec_root);
        move_to(account, CchsAccount {
            root,
            rec_root,
            epoch: 0,
            next_idx: 0,
            nonce: 0,
            rec_nonce: 0,
            cached_root: table::new<u128, vector<u8>>(),
        });
    }

    // ============================================================ execute

    /// Transfer `amount` octas of APT from the owner's account to `recipient`,
    /// authorized by a CCHS signature on the transfer digest.
    ///
    /// `l0_*` is the bottom-layer WOTS+ signature (67 x 32 bytes) and auth path
    /// (10 x 32 bytes) for leaf `next_idx`. `has_l1` / `l1_*` carry the
    /// top-layer proof, required on the first use of each bottom subtree.
    ///
    /// v1 note: the coin move uses `aptos_account::transfer`, which needs the
    /// owner's signer. A signer-free design (resource account holding a
    /// `SignerCapability`, arbitrary payloads) is planned for a later version.
    public entry fun execute_transfer(
        account: &signer,
        recipient: address,
        amount: u64,
        l0_wots: vector<vector<u8>>,
        l0_auth: vector<vector<u8>>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        let addr = signer::address_of(account);
        assert!(exists<CchsAccount>(addr), error::not_found(E_NOT_INIT));
        let acct = borrow_global_mut<CchsAccount>(addr);

        let idx = acct.next_idx;
        assert!(idx < CAPACITY, error::out_of_range(E_EXHAUSTED));

        let m = digest(addr, acct.nonce, idx, recipient, amount);
        verify_and_cache(acct, addr, idx, &m, &l0_wots, &l0_auth, has_l1, &l1_wots, &l1_auth);

        // effects before interaction
        acct.next_idx = idx + 1;
        acct.nonce = acct.nonce + 1;

        aptos_account::transfer(account, recipient, amount);
        event::emit(Executed { account: addr, idx, recipient, amount });
    }

    // ============================================================ recovery

    /// Rotate `root` and `rec_root`, authorized by the recovery tree.
    /// Resets `next_idx` and bumps `epoch` (logically clearing the cache).
    /// Callable by anyone holding a valid recovery signature.
    public entry fun recover(
        acct_addr: address,
        new_root: vector<u8>,
        new_rec_root: vector<u8>,
        wots: vector<vector<u8>>,
        auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        assert!(exists<CchsAccount>(acct_addr), error::not_found(E_NOT_INIT));
        assert_root(&new_root);
        assert_root(&new_rec_root);
        let acct = borrow_global_mut<CchsAccount>(acct_addr);

        let rn = acct.rec_nonce;
        assert!(rn < REC_CAPACITY, error::out_of_range(E_EXHAUSTED));

        let m = recovery_digest(acct_addr, rn, &new_root, &new_rec_root);
        let r = verify_layer(LAYER_REC, 0, rn, REC_H, &m, &wots, &auth);
        assert!(r == acct.rec_root, error::permission_denied(E_BAD_RECOVERY));

        acct.root = new_root;
        acct.rec_root = new_rec_root;
        acct.next_idx = 0;
        acct.epoch = acct.epoch + 1;
        acct.rec_nonce = rn + 1;
        event::emit(Recovered {
            account: acct_addr,
            new_epoch: acct.epoch,
            new_root: acct.root,
            new_rec_root: acct.rec_root,
        });
    }

    // ============================================================ views

    /// Digest the client must sign for the next `execute_transfer`.
    #[view]
    public fun next_digest(acct_addr: address, recipient: address, amount: u64): vector<u8> acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        digest(acct_addr, acct.nonce, acct.next_idx, recipient, amount)
    }

    /// Whether the next `execute_transfer` must include the top-layer proof.
    #[view]
    public fun needs_top_layer(acct_addr: address): bool acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        !table::contains(&acct.cached_root, cache_key(acct.epoch, acct.next_idx >> 10))
    }

    #[view]
    public fun root(acct_addr: address): vector<u8> acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).root }
    #[view]
    public fun rec_root(acct_addr: address): vector<u8> acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).rec_root }
    #[view]
    public fun epoch(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).epoch }
    #[view]
    public fun next_idx(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).next_idx }
    #[view]
    public fun nonce(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).nonce }
    #[view]
    public fun rec_nonce(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).rec_nonce }

    // ============================================================ internals

    fun assert_root(r: &vector<u8>) {
        assert!(vector::length(r) == 32, error::invalid_argument(E_BAD_LENGTH));
        assert!(*r != x"0000000000000000000000000000000000000000000000000000000000000000", error::invalid_argument(E_ZERO_ROOT));
    }

    fun cache_key(epoch: u64, tree_idx: u64): u128 {
        ((epoch as u128) << 64) | (tree_idx as u128)
    }

    /// M = sha2_256("AEGIS_CCHS_V1" || "aptos" || bcs(account) || nonce(8 BE) || idx(8 BE)
    ///              || sha2_256(bcs(recipient) || amount(8 BE)))
    fun digest(account: address, nonce: u64, idx: u64, recipient: address, amount: u64): vector<u8> {
        let action = bcs::to_bytes(&recipient);
        vector::append(&mut action, be64(amount));
        let action_hash = hash::sha2_256(action);

        let buf = b"AEGIS_CCHS_V1";
        vector::append(&mut buf, b"aptos");
        vector::append(&mut buf, bcs::to_bytes(&account));
        vector::append(&mut buf, be64(nonce));
        vector::append(&mut buf, be64(idx));
        vector::append(&mut buf, action_hash);
        hash::sha2_256(buf)
    }

    /// M_rec = sha2_256("AEGIS_CCHS_RECOVER_V1" || "aptos" || bcs(account) || rec_nonce(8 BE)
    ///                  || new_root || new_rec_root)
    fun recovery_digest(account: address, rec_nonce: u64, new_root: &vector<u8>, new_rec_root: &vector<u8>): vector<u8> {
        let buf = b"AEGIS_CCHS_RECOVER_V1";
        vector::append(&mut buf, b"aptos");
        vector::append(&mut buf, bcs::to_bytes(&account));
        vector::append(&mut buf, be64(rec_nonce));
        vector::append(&mut buf, *new_root);
        vector::append(&mut buf, *new_rec_root);
        hash::sha2_256(buf)
    }

    /// Layer-0 verification, then either cache equality or full top-layer
    /// verification with cache write. Aborts on any mismatch.
    fun verify_and_cache(
        acct: &mut CchsAccount,
        addr: address,
        idx: u64,
        m: &vector<u8>,
        l0_wots: &vector<vector<u8>>,
        l0_auth: &vector<vector<u8>>,
        has_l1: bool,
        l1_wots: &vector<vector<u8>>,
        l1_auth: &vector<vector<u8>>,
    ) {
        let tree_idx = idx >> 10;
        let leaf_idx = idx & 1023;
        let r0 = verify_layer(0, tree_idx, leaf_idx, H, m, l0_wots, l0_auth);

        let key = cache_key(acct.epoch, tree_idx);
        if (table::contains(&acct.cached_root, key)) {
            let cached = table::borrow(&acct.cached_root, key);
            assert!(*cached == r0, error::permission_denied(E_BAD_SUBTREE_ROOT));
            return
        };
        assert!(has_l1, error::invalid_argument(E_MISSING_TOP_LAYER));
        // Top layer: tree 0, leaf = tree_idx, message = r0.
        let r1 = verify_layer(1, 0, tree_idx, H, &r0, l1_wots, l1_auth);
        assert!(r1 == acct.root, error::permission_denied(E_BAD_TOP_ROOT));
        table::add(&mut acct.cached_root, key, r0);
        event::emit(SubtreeCached { account: addr, epoch: acct.epoch, tree_idx, subtree_root: r0 });
    }

    /// Recompute the root of tree (`layer`, `tree_idx`) of height `height`
    /// from a WOTS+ signature on `m` at `leaf_idx` and the auth path.
    /// Pure; byte-exact with `AegisCCHS._layerRoot`.
    public fun verify_layer(
        layer: u8,
        tree_idx: u64,
        leaf_idx: u64,
        height: u64,
        m: &vector<u8>,
        wots: &vector<vector<u8>>,
        auth: &vector<vector<u8>>,
    ): vector<u8> {
        assert!(vector::length(m) == 32, error::invalid_argument(E_BAD_LENGTH));
        assert!(vector::length(wots) == LEN, error::invalid_argument(E_BAD_LENGTH));
        assert!(vector::length(auth) == height, error::invalid_argument(E_BAD_LENGTH));

        let d = digits(m);

        // Leaf: sha2_256(adrs_leaf || pk_0 || ... || pk_66)
        let leaf_buf = adrs(layer, tree_idx, 0x01, leaf_idx, 0, 0);
        let c = 0;
        while (c < LEN) {
            let x = *vector::borrow(wots, c);
            assert!(vector::length(&x) == 32, error::invalid_argument(E_BAD_LENGTH));
            let s = *vector::borrow(&d, c);
            while (s < 15) {
                let input = adrs(layer, tree_idx, 0x00, leaf_idx, (c as u8), s);
                vector::append(&mut input, x);
                x = hash::sha2_256(input);
                s = s + 1;
            };
            vector::append(&mut leaf_buf, x);
            c = c + 1;
        };
        let node = hash::sha2_256(leaf_buf);

        // Auth path, leaf -> root.
        let pos = leaf_idx;
        let k = 0;
        while (k < height) {
            let sib = *vector::borrow(auth, k);
            assert!(vector::length(&sib) == 32, error::invalid_argument(E_BAD_LENGTH));
            let input = adrs(layer, tree_idx, 0x02, pos >> 1, (k as u8), 0);
            if ((pos & 1) == 0) {
                vector::append(&mut input, node);
                vector::append(&mut input, sib);
            } else {
                vector::append(&mut input, sib);
                vector::append(&mut input, node);
            };
            node = hash::sha2_256(input);
            pos = pos >> 1;
            k = k + 1;
        };
        node
    }

    /// 64 base-16 message digits followed by 3 base-16 checksum digits.
    public fun digits(m: &vector<u8>): vector<u8> {
        let d = vector::empty<u8>();
        let csum: u64 = 0;
        let i = 0;
        while (i < 32) {
            let b = *vector::borrow(m, i);
            let hi = b >> 4;
            let lo = b & 0x0f;
            vector::push_back(&mut d, hi);
            vector::push_back(&mut d, lo);
            csum = csum + (15 - (hi as u64)) + (15 - (lo as u64));
            i = i + 1;
        };
        // csum <= 960 < 16^3: three big-endian base-16 digits.
        vector::push_back(&mut d, (((csum >> 8) & 0x0f) as u8));
        vector::push_back(&mut d, (((csum >> 4) & 0x0f) as u8));
        vector::push_back(&mut d, ((csum & 0x0f) as u8));
        d
    }

    /// ADRS = layer(1) || tree_idx(8 BE) || type(1) || leaf_idx(4 BE) || chain_idx(1) || step(1) || pad(16 zero)
    public fun adrs(layer: u8, tree_idx: u64, typ: u8, leaf_idx: u64, chain_idx: u8, step: u8): vector<u8> {
        let a = vector::empty<u8>();
        vector::push_back(&mut a, layer);
        vector::append(&mut a, be64(tree_idx));
        vector::push_back(&mut a, typ);
        vector::append(&mut a, be32(leaf_idx));
        vector::push_back(&mut a, chain_idx);
        vector::push_back(&mut a, step);
        let i = 0;
        while (i < 16) {
            vector::push_back(&mut a, 0);
            i = i + 1;
        };
        a
    }

    /// Big-endian 8-byte encoding (BCS is little-endian; not used here).
    fun be64(x: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i: u8 = 0;
        while (i < 8) {
            let shift = (7 - i) * 8;
            vector::push_back(&mut out, (((x >> shift) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    /// Big-endian 4-byte encoding of the low 32 bits.
    fun be32(x: u64): vector<u8> {
        let out = vector::empty<u8>();
        let i: u8 = 0;
        while (i < 4) {
            let shift = (3 - i) * 8;
            vector::push_back(&mut out, (((x >> shift) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    // ============================================================ tests
    // Vectors: evm/test/fixtures/cchs-s-20.json (CCHS-S-20, master 0x07..07).

    #[test]
    fun test_adrs_layout() {
        let a = adrs(0x01, 0x0102030405060708, 0x02, 0x0a0b0c0d, 0x21, 0x0e);
        assert!(a == x"010102030405060708020a0b0c0d210e00000000000000000000000000000000", 0);
        assert!(vector::length(&a) == 32, 1);
    }

    #[test]
    fun test_digits_fixture_op1() {
        // ops[1].digest; checksum = 430 = 0x1AE -> digits 1, 10, 14.
        let m = x"7c06dfcdc83e3f42a32ee106be945deee21183c9a8563a2eab8450cbc7f1cede";
        let d = digits(&m);
        assert!(vector::length(&d) == 67, 0);
        assert!(d == x"070c00060d0f0c0d0c08030e030f04020a03020e0e0100060b0e0904050d0e0e0e02010108030c090a080506030a020e0a0b080405000c0b0c070f010c0e0d0e010a0e", 1);
    }

    #[test]
    fun test_layer0_fixture_op1_matches_bottom_root0() {
        // ops[1]: idx 1 -> tree 0, leaf 1, cached path (no top layer).
        let m = x"7c06dfcdc83e3f42a32ee106be945deee21183c9a8563a2eab8450cbc7f1cede";
        let r0 = verify_layer(0, 0, 1, 10, &m, &fixture_op1_l0_wots(), &fixture_op1_l0_auth());
        assert!(r0 == x"0e2f82e50284c90ccbf4cc9621789de2746ade4e231383eb2a89794db19ff80a", 0);
    }

    #[test]
    fun test_layer1_fixture_op0_matches_root() {
        // ops[0].l1: top layer, tree 0, leaf = tree_idx = 0, message = bottomRoot0.
        let r0 = x"0e2f82e50284c90ccbf4cc9621789de2746ade4e231383eb2a89794db19ff80a";
        let r1 = verify_layer(1, 0, 0, 10, &r0, &fixture_op0_l1_wots(), &fixture_op0_l1_auth());
        assert!(r1 == x"0db8112457679a25c1f76a03204a76986ba5f1c7bce2add2cce5a9e3591593c7", 0);
    }

    #[test]
    #[expected_failure]
    fun test_layer0_tampered_chain_fails() {
        let m = x"7c06dfcdc83e3f42a32ee106be945deee21183c9a8563a2eab8450cbc7f1cede";
        let wots = fixture_op1_l0_wots();
        *vector::borrow_mut(&mut wots, 3) = x"0000000000000000000000000000000000000000000000000000000000000000";
        let r0 = verify_layer(0, 0, 1, 10, &m, &wots, &fixture_op1_l0_auth());
        assert!(r0 == x"0e2f82e50284c90ccbf4cc9621789de2746ade4e231383eb2a89794db19ff80a", 0);
    }

    #[test_only]
    fun fixture_op1_l0_wots(): vector<vector<u8>> {
        vector[
            x"2ba2fd5a08e2ace460183c9cbf65f256e9f2df69c401078778f919d9213e09ae",
            x"465ae8facb833a2e8b586dfb55bd146a85b7451e0dcac795a68578f87f6e6069",
            x"5b7f98ecff37e2cd29b9adec3bcf1dc128bb005359828975d079eb4505c0ee9e",
            x"a91cfc65e05cc78482103689417e341842b9ca23ca8919a59f7643a4b8333e6c",
            x"e4cfe8de0a5b08b445f9152f4a7aa87a57cbeb26d45aa54029a3a2bb8b1429f2",
            x"1e3c4db9ff0a844d7075a8eb65068d0a0b3fe16b9a326204209968f6d61618d7",
            x"b46140dffe5a8db66685a4214904fd9bd594741a451cb142b3cffb82a93cdff9",
            x"82a7d811bbf3db7ab046ea1ad0b695dc43003ce5f4abce4f799a8818727df5da",
            x"fdd361dc4250c25c19e4ec35b821bd08a594de034b421cc8d7569394785c0389",
            x"6ae3b025d5f74e596ca422936cef0fa0a40cce3b6194cf076b8625a0a9b4cfaf",
            x"044360137cac085959120735430ecee6b70b091d87084226c3eb6cfbc23b9bfd",
            x"dd80d6d7bade858a6b73802c6997fc1ecfcf3aee174e82faf45762ec380e3f62",
            x"7737003ff5d3bf71e6abde54e9bc874e2ce4ef73ce2348b533f02909b4b2c830",
            x"51840135442eb59f7945d3febc37c5d0775822cf06330982449000833df2c457",
            x"111fada9f272e71e80daccf8a172c59ad0c54086737bb2f93a9653308f6afd19",
            x"35f420d52210b77abf29b1f94d77ccc5e48bf5141a871fef65da75de693749a0",
            x"08c1b22331c4750685f669ab95a5c64df92f32e4b84ff4ef07f5aeb3bce13a3b",
            x"a086521cfbaaf2421f4ec411c1aec1898ae91aa9b1191e821b4b4fb54bac1600",
            x"5af12f532342a99cb487894ed6726d547023020789852c5262c631f880b6c543",
            x"1448f9dabcccb3dbaa27f74da0bda5d0faace84e3729acdb495979233e0f9b05",
            x"7f6b037d035df8519e87190bb12b0c6e027b280fc3f71966d16f6b82e95db0b7",
            x"bf8e81b0b18e658f995449a9ab10e5f39c5b9490fadf9c0a8c1b87f00c170a43",
            x"2276097e8e89c615ced336109d565af438868b8978ed77301a4e27670607966e",
            x"e8b16fa15e95d3cd06482c1e0464cd8bd49589be455017a094868b808d7e6b8c",
            x"d6cefc33f5d189b1487a83329a3e628cc56ca8e6f7f1ccdf527acf34419ea17b",
            x"8a46f4fd4468ef4a67eaa45fd2018dfb9d8dbcbedf08cb7072971fa85f2b292a",
            x"58cbbd9479d6f0a89df1770e50cdbe776697086ba36db8c8a4dd3f543a660645",
            x"432352b4f849d24bbde7b7d6785ba25efc27ddd4244cfcb518a684a8e2a9b434",
            x"762df77329744bd934d3bfcbe94053f277206c1bf152e9fcc190826cae820b33",
            x"fe6b4b691383d9d1f2ed79a740e05d32260321a6b29a8b9ae9299c7a66669fde",
            x"b467ec3a8507aa44b2cbe357b7b9204ef92be99690f32d670b5b167078427fbe",
            x"ee75db88255924addc5c26c769ebc8c900c42d44487341e7478eae247fb21e0c",
            x"0ab95f648e8e778cf70e5aaac2f930b001b76f1be42b8de61269e98c97cfc7f4",
            x"fb7797aec1659c7426f8f4f77678780fca0ab0a06f6d3f0268add614c8ff25c9",
            x"805ef0e15b274db4e393feebd2fd75fcd006bb3d9446c0b9d8751c845c7d1834",
            x"3f5c715a541e14af56fcc0c4b317a492f850478518031bd0b6d598341ecb8750",
            x"7ed62848e47fa8b5058737f8b048f15c8587e7ccf335bdde827d22a30f49cf75",
            x"2d3a7daa90acfaaabbeae31f1a629813edf42072c86e93fa037f68671513d2ff",
            x"b6d91fcdbec380b91d21cd66a05b6835e6e16b512e3015a21583a8047bf9fe88",
            x"1d12193996e60e0cb4a0f0c4a67ddd593c62a3b8d18169748a73cf3b3526a8bc",
            x"e8cca7517ad6ddcaf0321c732cec09952a749009c2adc72742a2946de2e8dcf3",
            x"fa94854c9355b46de38a56af5e593f68d285b76116245aab32318b85477e79fd",
            x"0de452f0b8445c8b648b80619d8f9f99857ff0cbf526a9bc55236604b1cea1e6",
            x"a308955fc83adc5b8def964e52e0be96300711c7e3820e1a6645caf16104d110",
            x"c6a7de768d788648781eb7add258b127f1a3878e9305ad28b0520ac6fdf63c06",
            x"a0e61d0a8d475daf3b71c3dd00c0758e748e1be6049c5551946582a583a8e8fe",
            x"b9ff2862546ba0be8440f5768fb5e4ade5e4b495366863b338fa32464d2c9b2a",
            x"70975dc50603c763dfbebd254db85f3b9be138111e08e894dace312fcc69cc70",
            x"882bdcb29381ebad154c968250e0e86b699b2d54766de7686da70c51a6496d2b",
            x"44c1afe9f5813daa6c72e8ec517f75175ed42d5c3667d319817956c933e08b92",
            x"2a657054cbfce9fc52cdb2b19dfda707367303a13e18690e4be597332bf0321d",
            x"75a50e54edfd562c745365fd7e6fc00aedcbc0e41800323dadd6501d1acf00a7",
            x"e0fdd92bf83c6f4d7db9d7d8263dae5089825f1f8410e5557fda8451a5b84e0c",
            x"2f186825bae762094aa4ad822af781b434b58c34668e4d4d6862d69d5cfb390d",
            x"1a9e1a99c59d59e9cba12df4b999c0dc7ae89bb858cfbcc4c80305f5df18c071",
            x"04d94d19f6ba91fe18b6683de54e5bbb3320f2d44ae65a6b350e8df3fa47dd56",
            x"a98015850c7b5e8d694ff0d846bb55347120d38a2fac659fbd56e4c477e4bfed",
            x"d1d5f827706c8ac9122a89fef4104089e4effc7be8fcd88a8a8732fff67ed2c4",
            x"c6d152d257f44e5aff9c2bb0fb0087ae0ce59dadfa2575b4489e28586bccd0f9",
            x"656225d3f6d7eab16ec156bdceaff613653eaf84996bc3b345f40a9bebc2f860",
            x"a1ddd134063c7709f2630e76e22b9f3d49440de35249523f9d441e5d95db04d6",
            x"4a67f7ee50cc7e4a2de34b81b4e2fc0196f50a571c67f5a1cd9ea0c91b99c6ec",
            x"e2a615f935665cb77f6a75d86c66221de04245cd04a767463e9e0dc60442f7fa",
            x"9492cd5b201c29257daaa3e881de515a280de1accd7e31939db43e57bc3fc6e4",
            x"c5a0173470cb83b2520e9951a50258382ccabaaab0e697ab9d8b8dc52e28b124",
            x"57d6fdfb501e531588e0dec870191be7171f0402f55edf121452b2b515f9e84a",
            x"3433cea87206ddd1728b74549a7174f90dd3303ce822f77f480cb93ad2572add",
        ]
    }

    #[test_only]
    fun fixture_op1_l0_auth(): vector<vector<u8>> {
        vector[
            x"05d036257a8a6bf32c10a7d52fcc91d700dccbd57dd9feb74fd36517f3051ec0",
            x"d9062fbaacd1bb8b5b631d3f740f5bd4273ff1f5845dacc7e67f599a84417a3d",
            x"cd4d0c50d445073839b3e70fec476f8bd80c6112e50335ce772ab65e77e71640",
            x"5e72add3cb130b8fbea418d1f3b2a2a506feba02be382c6a102a047e202ee7e6",
            x"575335c4000842b2c80d0584c6509c92362474725f11085c3b3e85e3f6ef3b62",
            x"9a6609a09286b8d0102b29d242a358bd3f100be36fc89c1b3e2f7c6f0698707b",
            x"1bce46fe9ddd267125035bff246c715b3702d09d573d98f4143770cd8c5303ff",
            x"1521e03b61b9cf159eca6c3fe03ae55a686d619e6a160f502e95e0f0d4c95b01",
            x"b3551ec61ae4e21230b7ae9a4f408b9198ba80698773d5e202af0325c4b2b6cf",
            x"166f57c72b5c66002859c7b910151f2b5b8c51936f7215f16e7381796726bce8",
        ]
    }

    #[test_only]
    fun fixture_op0_l1_wots(): vector<vector<u8>> {
        vector[
            x"26299f57be2f391890ab3f5c3aead99474498e22b582272e4b7c299ac72fd2f0",
            x"4284f25cfcf2b0c3e5840c982fc08bb1c23e2a5df2fc3760c7f5a951dd95401a",
            x"ac30b133c6a96d63682e2ec9b12d3bac973da9171045bfbfc30bac2e7e8f47d9",
            x"6418297d02533e30f28cc8862c3690067869bd6f83e7b57dd0f4376826401c69",
            x"a88d4746eba990b00d47bec3931ea7b1e972fb323520554bc88f8bfe676e5c26",
            x"5893f800d84b32c955df8b05e059d40d6c41f273fbb23d755380a676c31f62da",
            x"2da612db5b95b9ab6736b9a7a6a8dddb100d204b92b01bb1854413ce3d5161d0",
            x"2e3591b22fc5e0274cec9aa3c2d129c861b67714da8659d53c50750679ef1dd2",
            x"17c9561352aa641e9aca97da851e8b4ee3b35b11306b113aaf1719738c5b7e30",
            x"274571e14b93703f8a6f30ae99e8a081386b103e012288d899f7eb7d3a3b7837",
            x"dfe971a61e5f957ce04fb78411908980cdf055390f79b53eabfb00a65fff53b5",
            x"ba4f27559e563bfa24c37d5ed27a8530d9b1a59251b983cd5b4999076650a6c8",
            x"5fa7742efe0931457b43f09137e2b03f0d19746041938ffec6620d463b256129",
            x"dbc59af4ecae61bbd34e2be095490deb185fd979cf29e0327b6a431a15b1b456",
            x"dbf9ea4117dccf68525b70360ae6e60b0a0ba6beed2cd35d15beb5e614c24120",
            x"208d7aa6448c6a2752d879cee25499b9c258a3bf3f0e2e99369c5d38ac8653f5",
            x"ae36180b84b8c4bc19e4f991ac47c11147823558d3faf7b529e0c8ba11aab3b9",
            x"c2c686592bc89b5e0cb0f3c7272fd7ff7d31a0a7d120ecd3d1b2f2eef247d062",
            x"792713d2901f342578393d2b6182ee8fa4818c22c299d8f87fb66dec0e9d8d64",
            x"6892622458385fb6566c7db0f8cb3ec0f955645731f0691af3145944e26f22ec",
            x"1a6792446ebd17dc61cd71fe8e58bb150a14ef018ffd52e47eb5c2e37163ee73",
            x"e9037e646f6f2468ecceff911b71135fe22c2de223b7e42c0c96696a6bcf1246",
            x"7e59a45391a4188d41ad18d1a7ec3027572b723367d19acb1b0bffcd8f2f4cf8",
            x"9d8806e51e09cd78bc9b8a623e8079f660d383c61cb433511076f49f647cd8ed",
            x"749ccdf1e7f8b934eea3d84fb335193812cf33161959f82483b6eb602356bccc",
            x"b567cfaf7686560c245ec227fde2a21f87b792b5200afa2907c7467299b57231",
            x"228ca76a83774ea663bd0407d35400e378206a74d7a73120cea258726a2f51e0",
            x"1ad419f75fd7b0973d274ea4014050292fa7bb55e0d0749621e98cec049dda20",
            x"9ed2bfd7a5b367f02523d1c3c97029d23f60494b6e9fb7c46dd9d64a3f1e3d82",
            x"165e08c2a79be2cad41dc73aebcd9f3a098b36faf683557e2dc198d25f2d6a79",
            x"242ed57a56860704e3aba5658cae7da26bc381a8784e2192734f9a47a1992c61",
            x"0c8beec77fc537c7355f6db92ba69fb537e5ea372ed5f75392237251dfd2363a",
            x"48d7dcd1de18c860d516fab2fff9e38d747f3a596c9f3d9604d56518c826ddaa",
            x"1bfa586dac80d7c4542e617968cf753a3dbd5e48aaa64d7df7f140e364413ca1",
            x"47336dd545f557b95c03a0dc6eecc4211fb258059e4e9230449af26ed1de48dc",
            x"13bc8d0c762df1499a0eee4344e81975a2dc8dd0514c56e7fe8e1b3c821defb3",
            x"9f656cf4a1320ab6ee3f8ee7cc23e376669e3652ee57cc85800ca45e8c19d307",
            x"b6522aa1cca9f2313fb34a54ed82b08d10ce80fd10b750dd35c621fbd86649f4",
            x"6079e851747446f3a71f449cc389755b286843cd219d1f3e40b1ca7ab0d7cde1",
            x"2d74a9f38c21c326cc1fe3c6fbfaab3c8fa3997cadf45b39eb64710115e39745",
            x"c1100e3b6a09d8a4c25f180e5a6be0f6c54c822ee9ecc8717919f52b3394aa58",
            x"c8b21f9504b31f5708abb1447aa8ae81857e46564b753aa098de6c6f17bb0639",
            x"9751dfda6e63569bd2cf1da6cb5c1a1c9c18bca203af3416457b9dbe726b4cce",
            x"ed771242321bb37a4f46356e116c227b4cb8e5c6b0167919d6b9fc3bb819c537",
            x"bd5d265668c05190ede986bcd129442fcdf370935e7cc135079b665978b5ebcb",
            x"453f876ab5aceb2aff5f4c9f7aebe88c8bc80e8bc83f243e5eff6d42a1493f14",
            x"33490b284f41cbcc2bf17d9eadb0b620d3620c3ce7574d88c3a2ce24d9b67ab5",
            x"6c3770d2292faef3a99433c77ce8f2f27e715c6a919ce3e591132c70a455fa11",
            x"61faeeddc488319caace91dfcccee6c31603283883142ce7b8c42f3fc0010ef8",
            x"2e33624b961249d8802a0a931bdb1ee42c54ed1ec1b30deafc4d7373d841f753",
            x"06d1435094665d5b8faa371b646277c6603a2ec98b7170dc9e536c7c4261ad82",
            x"2ed10c36d4f54d76ba45257fd595d3f4035bb5b940a739ecfd44f73f59294d87",
            x"bfdba8a60347a491fad944d40b1b17b0328872f25b2cb362d536843c46a7a23f",
            x"a398bb4823f91d0be807a01bd633a92945694685f8d0c3422b99feacdfd5c588",
            x"90ef89faaf08996a299742b0d6de19472c778f4026394235bf748b6c29dbc02d",
            x"6084b8f39b78c8761bb3c5cac8cfa110bd6d16a10d97b19fe8e28e2c775ad3be",
            x"ec4a9bf8aa0879f91c1980501a0af39f647f994d60427c585aa805b23d0dd221",
            x"c80de58882218fc26f98580894071d7c130d8480a0542e52cac8c68a4d5e317f",
            x"aac433cc9cae94b2012f6fe1096417e0712065321f21a5eddff714d79645faa8",
            x"cfde7c2763becdd2287feb905f9fc0046bf240143110186acd1d4dbc964d4596",
            x"9add6bab8caa9ff82672659b216f9307f897e1633035729fc8cea453ec324a7d",
            x"0585787e740569a53231b4697ce232ad34d86c8dbb6a1b66ebccf2044949fec7",
            x"1a443e96c2a87b3fa21222a0d5f910d50c606c74f12ab14a26b82fd312a8341c",
            x"44c280bf5f89953b8d40618e6f9ed90ed2ca367060b27d53e78be62cc3d98eff",
            x"e8c6e2fb70398cc5e443366b6f6c4db705b77bd36049e14b8412f0c982a9d093",
            x"964b86f10c103970df1208963d0d8e1febf59544bd9e0810a8adde4998d972fe",
            x"df4c92c232d7233ee0b960aa1cd2758130be9defffedaa269acc58aa404a75f4",
        ]
    }

    #[test_only]
    fun fixture_op0_l1_auth(): vector<vector<u8>> {
        vector[
            x"1cea5544e961226c23b3ced52dfa7caac6122e16116c42f6b2fec69ce014322a",
            x"6db136295add86a70bda1faef3d313ee76cc62bb190da64174a0830e402779e0",
            x"24c16ba45c79fb6e9c2d9efd57db949469d10acd2291d93a86cd9349752b7f73",
            x"8b1a64133f2604e05b9c800d59db40ef431077f8f91ff85b5be2d6e3ad05bd7c",
            x"da0f533344f582fc261b419d9290902af67b8bc3954a006a82ecb536190f65de",
            x"794c20f155652862b68fe89b43d47dd832dae1f9b34a7afac18c56425f3780d9",
            x"6a61356108c4e419c233ffbcf1a19b9e5421d1ec081f2786ab918d4f23f195b9",
            x"e644df9fc718de3078a319c5b8fa81810faa9b834371284a90d02f2ab12f9ca7",
            x"f9e5b7fead542699500a1eba7e6f82ae081e0a6a94560c661c074f92c08d4155",
            x"b0de967824fd295948d97a350d8bbae2456a4442a08916e85ed559cce16243a3",
        ]
    }
}
