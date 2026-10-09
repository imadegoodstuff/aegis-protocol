/// Aegis CCHS account on Sui (CCHS-S-20, Move 2024).
///
/// Hash-only post-quantum account authorization. Every operation is a WOTS+
/// signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of
/// height 10 + 10 (2^20 signatures). The top-layer proof for each bottom
/// subtree is verified once and cached in a `Table`; later signatures in
/// that subtree carry only the bottom layer.
///
/// No elliptic-curve key is in the authorization path. `CchsAccount` is a
/// shared object: nobody owns it, no function takes an owner signature, and
/// the transaction sender only pays gas. Funds of any coin type `T` are
/// held inside the object (`Bag` of `Balance<T>` keyed by type name) and
/// leave it only through `execute_transfer<T>`, gated by the CCHS signature.
///
/// Immutability requirement: after `sui client publish` the `UpgradeCap`
/// must be destroyed with `sui::package::make_immutable`; otherwise the
/// publisher's key could upgrade this package and take the funds. See
/// ../README.md for the exact command sequence and deployment models.
///
/// Byte-exact with `evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`
/// for ADRS, chain steps, leaf compression and Merkle nodes. Only the
/// message digest differs per chain (see `digest`). Spec: ../../CCHS.spec.md
module aegis::aegis_account {
    use std::ascii;
    use std::bcs;
    use std::hash;
    use std::type_name::{Self, TypeName};
    use sui::bag::{Self, Bag};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::table::{Self, Table};
    #[test_only]
    use sui::sui::SUI;
    #[test_only]
    use sui::test_scenario;

    // ------------------------------------------------------------ params
    const LEN: u64 = 67;           // 64 message chains + 3 checksum chains
    const H: u64 = 10;             // tree height per layer
    const REC_H: u64 = 8;          // recovery tree height
    const CAPACITY: u64 = 1048576; // 2^(2*H)
    const REC_CAPACITY: u64 = 256; // 2^REC_H
    const LAYER_REC: u8 = 0xFF;
    /// Asset-id kind tag bound into the digest (coin type).
    const ASSET_KIND_COIN: u8 = 0x00;

    // ------------------------------------------------------------ errors
    const EBadLength: u64 = 1;
    const EExhausted: u64 = 2;
    const EBadSubtreeRoot: u64 = 3;
    const EMissingTopLayer: u64 = 4;
    const EBadTopRoot: u64 = 5;
    const EBadRecovery: u64 = 6;
    const EZeroRoot: u64 = 7;
    const ENoBalance: u64 = 8;
    const EIndexUsed: u64 = 9;

    // ------------------------------------------------------------ state
    /// Shared object. Nobody owns it; authorization is purely the CCHS signature.
    public struct CchsAccount has key {
        id: UID,
        /// Top-layer tree root. Rotatable only via `recover`.
        root: vector<u8>,
        /// Recovery tree root (single layer, height 8).
        rec_root: vector<u8>,
        /// Increments on every recovery; namespaces `cached_root`.
        epoch: u64,
        /// Lowest leaf index still accepted, in [0, 2^20). Set to `idx + 1`
        /// by every successful operation; the signer chooses `idx`.
        next_idx: u64,
        /// Nonce bound into every message digest.
        nonce: u64,
        /// Next unused recovery leaf in [0, 256).
        rec_nonce: u64,
        /// key = (epoch << 64) | bottom_tree_idx  ->  verified bottom subtree root
        cached_root: Table<u128, vector<u8>>,
        /// `TypeName` of `T` -> `Balance<T>`, one entry per coin type held.
        balances: Bag,
    }

    // ------------------------------------------------------------ events
    public struct Created has copy, drop { account: address, root: vector<u8>, rec_root: vector<u8> }
    public struct Executed has copy, drop { account: address, idx: u64, asset: vector<u8>, recipient: address, amount: u64 }
    public struct SubtreeCached has copy, drop { account: address, epoch: u64, tree_idx: u64, subtree_root: vector<u8> }
    public struct Recovered has copy, drop { account: address, new_epoch: u64, new_root: vector<u8>, new_rec_root: vector<u8> }

    // ============================================================ create

    /// Create a new shared CCHS account. Any sender may call this; the
    /// sender keeps no authority over the object.
    entry fun create(root: vector<u8>, rec_root: vector<u8>, ctx: &mut TxContext) {
        assert_root(&root);
        assert_root(&rec_root);
        let id = object::new(ctx);
        let account = object::uid_to_address(&id);
        event::emit(Created { account, root, rec_root });
        transfer::share_object(CchsAccount {
            id,
            root,
            rec_root,
            epoch: 0,
            next_idx: 0,
            nonce: 0,
            rec_nonce: 0,
            cached_root: table::new<u128, vector<u8>>(ctx),
            balances: bag::new(ctx),
        });
    }

    /// Deposit a coin of any type into the account. Anyone may fund it.
    entry fun deposit<T>(acct: &mut CchsAccount, c: Coin<T>) {
        let key = asset_key<T>();
        if (bag::contains_with_type<TypeName, Balance<T>>(&acct.balances, key)) {
            let b: &mut Balance<T> = bag::borrow_mut(&mut acct.balances, key);
            balance::join(b, coin::into_balance(c));
        } else {
            bag::add(&mut acct.balances, key, coin::into_balance(c));
        }
    }

    // ============================================================ execute

    /// Send `amount` of `T` from the account's balance to `recipient`,
    /// authorized by a CCHS signature on the transfer digest.
    ///
    /// `idx` is the leaf index the signer chose. It must be `>= next_idx`;
    /// every lower leaf is abandoned forever (`next_idx` becomes `idx + 1`).
    /// Skipping is how a signer leaves behind a leaf whose signature was
    /// broadcast but never landed, or an entire subtree whose keys it no
    /// longer trusts. Only the signer can skip, because `idx` is bound into
    /// the digest.
    ///
    /// `l0_*` is the bottom-layer WOTS+ signature (67 x 32 bytes) and auth path
    /// (10 x 32 bytes) for leaf `idx`. `has_l1` / `l1_*` carry the top-layer
    /// proof: required when the subtree of `idx` is not yet registered for
    /// the current epoch, ignored (not rejected) when it already is, so a
    /// transaction prepared before another registration landed still succeeds.
    /// Anyone may submit the transaction; the signature is the only gate.
    entry fun execute_transfer<T>(
        acct: &mut CchsAccount,
        recipient: address,
        amount: u64,
        idx: u64,
        l0_wots: vector<vector<u8>>,
        l0_auth: vector<vector<u8>>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
        ctx: &mut TxContext,
    ) {
        let account = object::uid_to_address(&acct.id);
        check_index(acct, idx);

        let asset = asset_id<T>();
        let m = digest(account, acct.nonce, idx, asset, recipient, amount);
        let r0 = verify_bottom_layer(idx, &m, &l0_wots, &l0_auth);
        settle_subtree(acct, account, idx, r0, has_l1, &l1_wots, &l1_auth);

        // effects before interaction
        advance(acct, idx);

        let key = asset_key<T>();
        assert!(bag::contains_with_type<TypeName, Balance<T>>(&acct.balances, key), ENoBalance);
        let b: &mut Balance<T> = bag::borrow_mut(&mut acct.balances, key);
        let out = coin::take(b, amount, ctx);
        transfer::public_transfer(out, recipient);
        event::emit(Executed { account, idx, asset, recipient, amount });
    }

    // ============================================================ recovery

    /// Rotate `root` and `rec_root`, authorized by the recovery tree.
    /// Resets `next_idx` and bumps `epoch` (logically clearing the cache).
    entry fun recover(
        acct: &mut CchsAccount,
        new_root: vector<u8>,
        new_rec_root: vector<u8>,
        wots: vector<vector<u8>>,
        auth: vector<vector<u8>>,
    ) {
        assert_root(&new_root);
        assert_root(&new_rec_root);
        let account = object::uid_to_address(&acct.id);

        let rn = acct.rec_nonce;
        assert!(rn < REC_CAPACITY, EExhausted);

        let m = recovery_digest(account, rn, &new_root, &new_rec_root);
        let r = verify_layer(LAYER_REC, 0, rn, REC_H, &m, &wots, &auth);
        assert!(r == acct.rec_root, EBadRecovery);

        acct.root = new_root;
        acct.rec_root = new_rec_root;
        acct.next_idx = 0;
        acct.epoch = acct.epoch + 1;
        acct.rec_nonce = rn + 1;
        event::emit(Recovered {
            account,
            new_epoch: acct.epoch,
            new_root: acct.root,
            new_rec_root: acct.rec_root,
        });
    }

    // ============================================================ views

    /// Asset id for coin type `T`: sha2_256(0x00 || ascii(type_name::with_defining_ids<T>())).
    /// For SUI the name is "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI".
    public fun asset_id<T>(): vector<u8> {
        let mut buf = vector::singleton(ASSET_KIND_COIN);
        vector::append(&mut buf, ascii::into_bytes(type_name::into_string(asset_key<T>())));
        hash::sha2_256(buf)
    }

    /// Digest the client must sign for an `execute_transfer<T>` at leaf `idx`
    /// (`idx >= next_idx`) with the current nonce.
    public fun digest_at<T>(acct: &CchsAccount, idx: u64, recipient: address, amount: u64): vector<u8> {
        digest(object::uid_to_address(&acct.id), acct.nonce, idx, asset_id<T>(), recipient, amount)
    }

    /// Digest for an `execute_transfer<T>` at `next_idx`.
    public fun next_digest<T>(acct: &CchsAccount, recipient: address, amount: u64): vector<u8> {
        digest_at<T>(acct, acct.next_idx, recipient, amount)
    }

    /// Digest the client must sign for the next `recover`.
    public fun next_recovery_digest(acct: &CchsAccount, new_root: vector<u8>, new_rec_root: vector<u8>): vector<u8> {
        recovery_digest(object::uid_to_address(&acct.id), acct.rec_nonce, &new_root, &new_rec_root)
    }

    /// Whether an `execute_transfer` at leaf `idx` must include the top-layer proof.
    public fun needs_top_layer_at(acct: &CchsAccount, idx: u64): bool {
        !table::contains(&acct.cached_root, cache_key(acct.epoch, idx >> 10))
    }

    /// Whether an `execute_transfer` at `next_idx` must include the top-layer proof.
    public fun needs_top_layer(acct: &CchsAccount): bool {
        needs_top_layer_at(acct, acct.next_idx)
    }

    public fun root(acct: &CchsAccount): vector<u8> { acct.root }
    public fun rec_root(acct: &CchsAccount): vector<u8> { acct.rec_root }
    public fun epoch(acct: &CchsAccount): u64 { acct.epoch }
    public fun next_idx(acct: &CchsAccount): u64 { acct.next_idx }
    public fun nonce(acct: &CchsAccount): u64 { acct.nonce }
    public fun rec_nonce(acct: &CchsAccount): u64 { acct.rec_nonce }

    /// Balance of `T` held by the account (0 if none was ever deposited).
    public fun balance_value<T>(acct: &CchsAccount): u64 {
        let key = asset_key<T>();
        if (bag::contains_with_type<TypeName, Balance<T>>(&acct.balances, key)) {
            let b: &Balance<T> = bag::borrow(&acct.balances, key);
            balance::value(b)
        } else {
            0
        }
    }

    // ============================================================ internals

    fun asset_key<T>(): TypeName { type_name::with_defining_ids<T>() }

    fun assert_root(r: &vector<u8>) {
        assert!(vector::length(r) == 32, EBadLength);
        assert!(*r != x"0000000000000000000000000000000000000000000000000000000000000000", EZeroRoot);
    }

    fun cache_key(epoch: u64, tree_idx: u64): u128 {
        ((epoch as u128) << 64) | (tree_idx as u128)
    }

    /// M = sha2_256("AEGIS_CCHS_V1" || "sui" || object_id(32) || nonce(8 BE) || idx(8 BE)
    ///              || sha2_256(asset || recipient(32) || amount(8 BE)))
    fun digest(account: address, nonce: u64, idx: u64, asset: vector<u8>, recipient: address, amount: u64): vector<u8> {
        let mut action = asset;
        vector::append(&mut action, bcs::to_bytes(&recipient));
        vector::append(&mut action, be64(amount));
        let action_hash = hash::sha2_256(action);

        let mut buf = b"AEGIS_CCHS_V1";
        vector::append(&mut buf, b"sui");
        vector::append(&mut buf, bcs::to_bytes(&account));
        vector::append(&mut buf, be64(nonce));
        vector::append(&mut buf, be64(idx));
        vector::append(&mut buf, action_hash);
        hash::sha2_256(buf)
    }

    /// M_rec = sha2_256("AEGIS_CCHS_RECOVER_V1" || "sui" || object_id(32) || rec_nonce(8 BE)
    ///                  || new_root || new_rec_root)
    fun recovery_digest(account: address, rec_nonce: u64, new_root: &vector<u8>, new_rec_root: &vector<u8>): vector<u8> {
        let mut buf = b"AEGIS_CCHS_RECOVER_V1";
        vector::append(&mut buf, b"sui");
        vector::append(&mut buf, bcs::to_bytes(&account));
        vector::append(&mut buf, be64(rec_nonce));
        vector::append(&mut buf, *new_root);
        vector::append(&mut buf, *new_rec_root);
        hash::sha2_256(buf)
    }

    /// Index discipline: the signer-chosen leaf must not be behind `next_idx`
    /// and must exist in the 2^20 index space.
    fun check_index(acct: &CchsAccount, idx: u64) {
        assert!(idx >= acct.next_idx, EIndexUsed);
        assert!(idx < CAPACITY, EExhausted);
    }

    /// Counter update after a verified operation at `idx`: every leaf below
    /// `idx` is abandoned, and the nonce moves on.
    fun advance(acct: &mut CchsAccount, idx: u64) {
        acct.next_idx = idx + 1;
        acct.nonce = acct.nonce + 1;
    }

    /// Bottom-layer root recomputed from the WOTS+ signature on `m` at leaf `idx`.
    fun verify_bottom_layer(
        idx: u64,
        m: &vector<u8>,
        l0_wots: &vector<vector<u8>>,
        l0_auth: &vector<vector<u8>>,
    ): vector<u8> {
        verify_layer(0, idx >> 10, idx & 1023, H, m, l0_wots, l0_auth)
    }

    /// Given the recomputed bottom root `r0` of the subtree of `idx`: if the
    /// subtree is registered for this epoch, require equality with the cached
    /// root and ignore any supplied top layer; otherwise require the top
    /// layer, verify it against `root` and register `r0`. Aborts on mismatch.
    fun settle_subtree(
        acct: &mut CchsAccount,
        account: address,
        idx: u64,
        r0: vector<u8>,
        has_l1: bool,
        l1_wots: &vector<vector<u8>>,
        l1_auth: &vector<vector<u8>>,
    ) {
        let tree_idx = idx >> 10;
        let key = cache_key(acct.epoch, tree_idx);
        if (table::contains(&acct.cached_root, key)) {
            let cached = table::borrow(&acct.cached_root, key);
            assert!(*cached == r0, EBadSubtreeRoot);
            return
        };
        assert!(has_l1, EMissingTopLayer);
        // Top layer: tree 0, leaf = tree_idx, message = r0.
        let r1 = verify_layer(1, 0, tree_idx, H, &r0, l1_wots, l1_auth);
        assert!(r1 == acct.root, EBadTopRoot);
        table::add(&mut acct.cached_root, key, r0);
        event::emit(SubtreeCached { account, epoch: acct.epoch, tree_idx, subtree_root: r0 });
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
        assert!(vector::length(m) == 32, EBadLength);
        assert!(vector::length(wots) == LEN, EBadLength);

        let d = digits(m);

        // Leaf: sha2_256(adrs_leaf || pk_0 || ... || pk_66)
        let mut leaf_buf = adrs(layer, tree_idx, 0x01, leaf_idx, 0, 0);
        let mut c: u64 = 0;
        while (c < LEN) {
            let mut x = *vector::borrow(wots, c);
            assert!(vector::length(&x) == 32, EBadLength);
            let mut s = *vector::borrow(&d, c);
            while (s < 15) {
                let mut input = adrs(layer, tree_idx, 0x00, leaf_idx, (c as u8), s);
                vector::append(&mut input, x);
                x = hash::sha2_256(input);
                s = s + 1;
            };
            vector::append(&mut leaf_buf, x);
            c = c + 1;
        };
        merkle_root(layer, tree_idx, leaf_idx, height, hash::sha2_256(leaf_buf), auth)
    }

    /// Auth path, leaf -> root: node_k = sha2_256(adrs(layer, tree, 0x02, pos >> 1, k, 0) || left || right).
    public fun merkle_root(
        layer: u8,
        tree_idx: u64,
        leaf_idx: u64,
        height: u64,
        node: vector<u8>,
        auth: &vector<vector<u8>>,
    ): vector<u8> {
        assert!(vector::length(auth) == height, EBadLength);
        let mut node = node;
        let mut pos = leaf_idx;
        let mut k: u64 = 0;
        while (k < height) {
            let sib = *vector::borrow(auth, k);
            assert!(vector::length(&sib) == 32, EBadLength);
            let mut input = adrs(layer, tree_idx, 0x02, pos >> 1, (k as u8), 0);
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
        let mut d = vector::empty<u8>();
        let mut csum: u64 = 0;
        let mut i: u64 = 0;
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
        let mut a = vector::empty<u8>();
        vector::push_back(&mut a, layer);
        vector::append(&mut a, be64(tree_idx));
        vector::push_back(&mut a, typ);
        vector::append(&mut a, be32(leaf_idx));
        vector::push_back(&mut a, chain_idx);
        vector::push_back(&mut a, step);
        let mut i: u64 = 0;
        while (i < 16) {
            vector::push_back(&mut a, 0u8);
            i = i + 1;
        };
        a
    }

    /// Big-endian 8-byte encoding (BCS is little-endian; not used here).
    fun be64(x: u64): vector<u8> {
        let mut out = vector::empty<u8>();
        let mut i: u8 = 0;
        while (i < 8) {
            let shift = (7 - i) * 8;
            vector::push_back(&mut out, (((x >> shift) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    /// Big-endian 4-byte encoding of the low 32 bits.
    fun be32(x: u64): vector<u8> {
        let mut out = vector::empty<u8>();
        let mut i: u8 = 0;
        while (i < 4) {
            let shift = (3 - i) * 8;
            vector::push_back(&mut out, (((x >> shift) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    // ============================================================ tests
    // Vectors: evm/test/fixtures/cchs-s-20.json (CCHS-S-20, master 0x07..07).
    // Digest vectors were recomputed independently with Node's crypto module
    // from the byte layouts documented above.

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
        let mut wots = fixture_op1_l0_wots();
        *vector::borrow_mut(&mut wots, 3) = x"0000000000000000000000000000000000000000000000000000000000000000";
        let r0 = verify_layer(0, 0, 1, 10, &m, &wots, &fixture_op1_l0_auth());
        assert!(r0 == x"0e2f82e50284c90ccbf4cc9621789de2746ade4e231383eb2a89794db19ff80a", 0);
    }

    #[test]
    fun test_asset_id_and_digest_vectors() {
        let name = ascii::into_bytes(type_name::into_string(asset_key<SUI>()));
        assert!(name == b"0000000000000000000000000000000000000000000000000000000000000002::sui::SUI", 0);
        let sui = asset_id<SUI>();
        assert!(sui == x"bccbbf91e43e347c81f378bf1e03af44a87c9a3819067862aa38e9a1a0114764", 1);
        // account 0xcafe, nonce 0, idx 0, SUI, recipient 0xb0b, amount 400
        let m = digest(@0xcafe, 0, 0, sui, @0xb0b, 400);
        assert!(m == x"96a85d1219011a466c044813c71af0f646e6a19c8c199f0f76a395e637846eb8", 2);
        let root = x"1111111111111111111111111111111111111111111111111111111111111111";
        let rec_root = x"2222222222222222222222222222222222222222222222222222222222222222";
        let mr = recovery_digest(@0xcafe, 0, &root, &rec_root);
        assert!(mr == x"834674aed2d0e06a52fc60c9b36152be49a9ab720794382e8afc14068fa9ce81", 3);
    }

    #[test]
    fun test_create_deposit_execute_first_in_subtree() {
        let creator = @0xa11ce;
        let bob = @0xb0b;
        let mut ts = test_scenario::begin(creator);

        let r0 = TEST_ROOT_L0;
        let top_root = TEST_TOP_ROOT;
        create(top_root, TEST_REC_ROOT, test_scenario::ctx(&mut ts));

        // A different sender funds and submits: no owner key exists.
        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));
        assert!(balance_value<SUI>(&acct) == 1000, 0);
        assert!(needs_top_layer(&acct), 1);

        let m0 = next_digest<SUI>(&acct, bob, 400);
        assert!(m0 == digest_at<SUI>(&acct, 0, bob, 400), 6);
        execute_transfer<SUI>(
            &mut acct, bob, 400, 0,
            test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, false),
            true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false),
            test_scenario::ctx(&mut ts),
        );
        assert!(balance_value<SUI>(&acct) == 600, 2);
        assert!(next_idx(&acct) == 1 && nonce(&acct) == 1, 3);
        assert!(!needs_top_layer(&acct), 4);
        test_scenario::return_shared(acct);

        test_scenario::next_tx(&mut ts, bob);
        let c = test_scenario::take_from_sender<Coin<SUI>>(&ts);
        assert!(coin::value(&c) == 400, 5);
        coin::burn_for_testing(c);
        test_scenario::end(ts);
    }

    #[test]
    fun test_cached_second_op() {
        let bob = @0xb0b;
        let mut ts = test_scenario::begin(@0xa11ce);

        // Bottom tree 0 with real leaves 0 and 1 (shared root).
        let r0 = TEST_ROOT_L0_REAL_SIBLING;
        let top_root = TEST_TOP_ROOT;
        create(top_root, TEST_REC_ROOT, test_scenario::ctx(&mut ts));

        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));

        let m0 = next_digest<SUI>(&acct, bob, 400);
        execute_transfer<SUI>(
            &mut acct, bob, 400, 0,
            test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, true),
            true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false),
            test_scenario::ctx(&mut ts),
        );
        // Cached subtree: bottom layer only.
        let m1 = next_digest<SUI>(&acct, bob, 100);
        execute_transfer<SUI>(
            &mut acct, bob, 100, 1,
            test_sign(0, 0, 1, &m1), test_auth(0, 0, 1, H, true),
            false, vector::empty(), vector::empty(),
            test_scenario::ctx(&mut ts),
        );
        assert!(balance_value<SUI>(&acct) == 500, 0);
        assert!(next_idx(&acct) == 2 && nonce(&acct) == 2, 1);
        assert!(!needs_top_layer(&acct), 2);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    fun test_recover_rotates_roots_and_keeps_funds() {
        let mut ts = test_scenario::begin(@0xa11ce);
        create(TEST_TOP_ROOT, TEST_REC_ROOT, test_scenario::ctx(&mut ts));

        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));

        // Recovery rotates the roots; object id and funds stay.
        let new_root = x"3333333333333333333333333333333333333333333333333333333333333333";
        let new_rec = x"4444444444444444444444444444444444444444444444444444444444444444";
        let mr = next_recovery_digest(&acct, new_root, new_rec);
        recover(&mut acct, new_root, new_rec, test_sign(LAYER_REC, 0, 0, &mr), test_auth(LAYER_REC, 0, 0, REC_H, false));
        assert!(root(&acct) == new_root && rec_root(&acct) == new_rec, 0);
        assert!(epoch(&acct) == 1 && next_idx(&acct) == 0 && rec_nonce(&acct) == 1, 1);
        assert!(needs_top_layer(&acct), 2);
        assert!(balance_value<SUI>(&acct) == 1000, 3);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EBadSubtreeRoot)]
    fun test_replayed_signature_fails() {
        let bob = @0xb0b;
        let mut ts = test_scenario::begin(@0xa11ce);
        let r0 = TEST_ROOT_L0;
        let top_root = TEST_TOP_ROOT;
        create(top_root, TEST_REC_ROOT, test_scenario::ctx(&mut ts));
        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));

        let m0 = next_digest<SUI>(&acct, bob, 400);
        let l0 = test_sign(0, 0, 0, &m0);
        let a0 = test_auth(0, 0, 0, H, false);
        execute_transfer<SUI>(&mut acct, bob, 400, 0, l0, a0, true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false), test_scenario::ctx(&mut ts));
        // Same signature submitted at the next free leaf: the index and the
        // nonce are both in the digest, so the recomputed subtree root
        // differs from the cached one. (At its own leaf 0 it fails earlier,
        // with EIndexUsed; see test_index_reuse_fails.)
        execute_transfer<SUI>(&mut acct, bob, 400, 1, l0, a0, false, vector::empty(), vector::empty(), test_scenario::ctx(&mut ts));
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EMissingTopLayer)]
    fun test_first_use_without_top_layer_fails() {
        let bob = @0xb0b;
        let mut ts = test_scenario::begin(@0xa11ce);
        let top_root = TEST_TOP_ROOT;
        create(top_root, TEST_REC_ROOT, test_scenario::ctx(&mut ts));
        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));
        let m0 = next_digest<SUI>(&acct, bob, 400);
        execute_transfer<SUI>(&mut acct, bob, 400, 0, test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, false), false, vector::empty(), vector::empty(), test_scenario::ctx(&mut ts));
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EBadTopRoot)]
    fun test_wrong_amount_fails() {
        let bob = @0xb0b;
        let mut ts = test_scenario::begin(@0xa11ce);
        let r0 = TEST_ROOT_L0;
        let top_root = TEST_TOP_ROOT;
        create(top_root, TEST_REC_ROOT, test_scenario::ctx(&mut ts));
        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        deposit<SUI>(&mut acct, coin::mint_for_testing<SUI>(1000, test_scenario::ctx(&mut ts)));
        // Signed for 400, submitted for 900: the bottom root no longer matches
        // the top-layer message, so the top layer fails against `root`.
        let m0 = next_digest<SUI>(&acct, bob, 400);
        execute_transfer<SUI>(&mut acct, bob, 900, 0, test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, false), true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false), test_scenario::ctx(&mut ts));
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    // ---- signer-chosen index. These tests exercise the index discipline,
    // the cache lookup by (epoch, tree) and the top-layer rule through
    // `test_apply`, which runs the state transition of `execute_transfer`
    // around an already-known bottom root instead of paying for a
    // bottom-layer WOTS+ verification per operation. Each test then costs
    // one or two top-layer verifications at most, which is what keeps it
    // under the computation cap. The bottom root of subtree 1 is an
    // arbitrary value: only the top-layer signature over it is verified.

    #[test_only]
    const TEST_ROOT_L0_T1: vector<u8> = x"5151515151515151515151515151515151515151515151515151515151515151";

    /// Account under the top tree whose leaves 0 and 1 are real, with
    /// subtree 0 registered through leaf 0 (`next_idx` = 1, `nonce` = 1).
    #[test_only]
    fun test_account_with_subtree0(): (test_scenario::Scenario, CchsAccount) {
        let mut ts = test_scenario::begin(@0xa11ce);
        create(TEST_TOP_ROOT_REAL_SIBLING, TEST_REC_ROOT, test_scenario::ctx(&mut ts));
        test_scenario::next_tx(&mut ts, @0xfee);
        let mut acct = test_scenario::take_shared<CchsAccount>(&ts);
        assert!(needs_top_layer_at(&acct, 0), 100);
        let (w, a) = test_top_layer(0, TEST_ROOT_L0);
        test_apply(&mut acct, 0, TEST_ROOT_L0, true, w, a);
        assert!(next_idx(&acct) == 1 && nonce(&acct) == 1, 101);
        assert!(!needs_top_layer(&acct), 102);
        (ts, acct)
    }

    /// Top-layer proof under `TEST_TOP_ROOT_REAL_SIBLING`: WOTS+ signature of
    /// top leaf `tree_idx` on the bottom root `r0`, plus its auth path.
    #[test_only]
    fun test_top_layer(tree_idx: u64, r0: vector<u8>): (vector<vector<u8>>, vector<vector<u8>>) {
        (test_sign(1, 0, tree_idx, &r0), test_auth(1, 0, tree_idx, H, true))
    }

    #[test]
    fun test_skip_within_subtree_and_across_subtrees() {
        let (ts, mut acct) = test_account_with_subtree0();
        // Leaves 1..4 are skipped inside the registered subtree: cached path.
        assert!(!needs_top_layer_at(&acct, 5), 0);
        test_apply(&mut acct, 5, TEST_ROOT_L0, false, vector::empty(), vector::empty());
        assert!(next_idx(&acct) == 6 && nonce(&acct) == 2, 1);
        // Jump to the first leaf of subtree 1: top leaf 1 must be presented.
        assert!(needs_top_layer_at(&acct, 1024), 2);
        assert!(!needs_top_layer(&acct), 3); // next_idx = 6 is still in subtree 0
        let (w, a) = test_top_layer(1, TEST_ROOT_L0_T1);
        test_apply(&mut acct, 1024, TEST_ROOT_L0_T1, true, w, a);
        assert!(next_idx(&acct) == 1025 && nonce(&acct) == 3, 4);
        assert!(!needs_top_layer_at(&acct, 1024) && !needs_top_layer(&acct), 5);
        assert!(*table::borrow(&acct.cached_root, cache_key(0, 1)) == TEST_ROOT_L0_T1, 6);
        assert!(*table::borrow(&acct.cached_root, cache_key(0, 0)) == TEST_ROOT_L0, 7);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EIndexUsed)]
    fun test_index_reuse_fails() {
        let (ts, mut acct) = test_account_with_subtree0();
        test_apply(&mut acct, 5, TEST_ROOT_L0, false, vector::empty(), vector::empty());
        // Abandoned leaves stay abandoned: 3 < next_idx = 6.
        test_apply(&mut acct, 3, TEST_ROOT_L0, false, vector::empty(), vector::empty());
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EIndexUsed)]
    fun test_same_index_twice_fails() {
        let (ts, mut acct) = test_account_with_subtree0();
        // Leaf 0 was consumed by the registration; it is rejected before any hashing.
        test_apply(&mut acct, 0, TEST_ROOT_L0, false, vector::empty(), vector::empty());
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EExhausted)]
    fun test_index_beyond_capacity_fails() {
        let (ts, mut acct) = test_account_with_subtree0();
        test_apply(&mut acct, CAPACITY, TEST_ROOT_L0, false, vector::empty(), vector::empty());
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EMissingTopLayer)]
    fun test_jump_to_fresh_subtree_without_top_layer_fails() {
        let (ts, mut acct) = test_account_with_subtree0();
        test_apply(&mut acct, 1024, TEST_ROOT_L0_T1, false, vector::empty(), vector::empty());
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    fun test_redundant_top_layer_is_ignored() {
        let (ts, mut acct) = test_account_with_subtree0();
        // A transaction prepared with the top layer before subtree 0 was
        // registered by someone else still succeeds: the proof is ignored.
        let (w, a) = test_top_layer(0, TEST_ROOT_L0);
        test_apply(&mut acct, 1, TEST_ROOT_L0, true, w, a);
        assert!(next_idx(&acct) == 2 && nonce(&acct) == 2, 0);
        // Ignored means not inspected: only the cached root is compared.
        test_apply(&mut acct, 2, TEST_ROOT_L0, true, vector::empty(), vector::empty());
        assert!(next_idx(&acct) == 3 && nonce(&acct) == 3, 1);
        assert!(*table::borrow(&acct.cached_root, cache_key(0, 0)) == TEST_ROOT_L0, 2);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    #[expected_failure(abort_code = aegis::aegis_account::EBadSubtreeRoot)]
    fun test_bottom_root_mismatch_in_registered_subtree_fails() {
        let (ts, mut acct) = test_account_with_subtree0();
        // A bottom root that is not the registered one is rejected even with a
        // (redundant) top layer attached: the cache, not the proof, decides.
        let (w, a) = test_top_layer(0, TEST_ROOT_L0);
        test_apply(&mut acct, 5, TEST_ROOT_L0_T1, true, w, a);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
    }

    #[test]
    fun test_digest_at_binds_index() {
        let mut ts = test_scenario::begin(@0xa11ce);
        create(TEST_TOP_ROOT, TEST_REC_ROOT, test_scenario::ctx(&mut ts));
        test_scenario::next_tx(&mut ts, @0xfee);
        let acct = test_scenario::take_shared<CchsAccount>(&ts);
        let d5 = digest_at<SUI>(&acct, 5, @0xb0b, 400);
        let d6 = digest_at<SUI>(&acct, 6, @0xb0b, 400);
        assert!(d5 != d6, 0);
        assert!(next_digest<SUI>(&acct, @0xb0b, 400) == digest_at<SUI>(&acct, 0, @0xb0b, 400), 1);
        test_scenario::return_shared(acct);
        test_scenario::end(ts);
        // Independent vectors: account 0xcafe, nonce 1, SUI, recipient 0xb0b, amount 400.
        let sui = asset_id<SUI>();
        assert!(digest(@0xcafe, 1, 5, sui, @0xb0b, 400) == x"57c2625c772a5aebfc1c9b94e6e7ad9a11dbd619434b83686ad333bb681ac3a8", 2);
        assert!(digest(@0xcafe, 1, 6, sui, @0xb0b, 400) == x"b954afffd6bdf1c9975d5cf742fdfaabf734e4fd026088d2155bca2da7756fb4", 3);
    }

    // ---- fixture vectors for the signer-chosen index (`skip.ops` in
    // evm/test/fixtures/cchs-s-20.json). The leaf hashes were derived from the
    // fixture with the client code in wallet/src/aegis/cchs.ts: every WOTS+
    // chain of `skip.ops[i].l0.wots` (resp. `.l1.wots`) is completed from the
    // digit of the signed message up to step 15 and the 67 chain ends are
    // compressed under the leaf ADRS. Checking the Merkle path alone (10
    // hashes) binds the fixture's auth paths and roots at a negligible cost;
    // one full `verify_layer` on `skip.ops[1].l0` covers the WOTS+ part with
    // tree index 1 in every ADRS.

    /// Leaf 5 of bottom tree 0 (`skip.ops[0]`, idx 5).
    #[test_only]
    const FIXTURE_LEAF_L0_T0_5: vector<u8> = x"338da9f9647caaf75368844a0f8bf933aa32be8f37aa86af4e4aa85c56b74da1";
    /// Leaf 0 of bottom tree 1 (`skip.ops[1]`, idx 1024).
    #[test_only]
    const FIXTURE_LEAF_L0_T1_0: vector<u8> = x"618932b666d7a32e3b50ca0b707adfb5a20748e201efb3e6a05c03c7f744bf53";
    /// Top-layer leaf 0 (signs `bottomRoot0`; sibling of top leaf 1, so it is `skip.ops[1].l1.auth[0]`).
    #[test_only]
    const FIXTURE_LEAF_L1_T0_0: vector<u8> = x"4d3620a6d258ffe53e42bb9b69db12718969ce6c75f3372d86303120292b7c50";
    /// Top-layer leaf 1 (signs `bottomRoot1`; sibling of top leaf 0, so it is `ops[0].l1.auth[0]`).
    #[test_only]
    const FIXTURE_LEAF_L1_T0_1: vector<u8> = x"1cea5544e961226c23b3ced52dfa7caac6122e16116c42f6b2fec69ce014322a";
    #[test_only]
    const FIXTURE_ROOT: vector<u8> = x"0db8112457679a25c1f76a03204a76986ba5f1c7bce2add2cce5a9e3591593c7";
    #[test_only]
    const FIXTURE_BOTTOM_ROOT0: vector<u8> = x"0e2f82e50284c90ccbf4cc9621789de2746ade4e231383eb2a89794db19ff80a";
    #[test_only]
    const FIXTURE_BOTTOM_ROOT1: vector<u8> = x"607bed1784b23c544c2ac23126d2fa5582e7cf20fd3e31922c3d530cef965a7b";

    #[test]
    fun test_fixture_skip_leaf5_path_matches_bottom_root0() {
        assert!(merkle_root(0, 0, 5, H, FIXTURE_LEAF_L0_T0_5, &fixture_skip_a_l0_auth()) == FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_fixture_skip_leaf5_at_shifted_index_mismatches() {
        // Leaf 5's material presented as leaf 6: the position flips the node
        // order and changes every node ADRS, so the subtree root differs and
        // an `execute_transfer` at idx 6 with this signature aborts with
        // EBadSubtreeRoot. (The WOTS+ digits would differ as well, since the
        // index is in the digest.)
        assert!(merkle_root(0, 0, 6, H, FIXTURE_LEAF_L0_T0_5, &fixture_skip_a_l0_auth()) != FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_fixture_skip_leaf1024_path_matches_bottom_root1() {
        assert!(merkle_root(0, 1, 0, H, FIXTURE_LEAF_L0_T1_0, &fixture_skip_b_l0_auth()) == FIXTURE_BOTTOM_ROOT1, 0);
    }

    #[test]
    fun test_fixture_skip_leaf1024_full_layer0_matches_bottom_root1() {
        // skip.ops[1]: idx 1024 -> tree 1, leaf 0; the signed message is skip.ops[1].digest.
        let m = x"b66cd1ee383ae8930b7afea625bb3e949cef3ca216c52d800f78c85c8a659c33";
        let r0 = verify_layer(0, 1, 0, H, &m, &fixture_skip_b_l0_wots(), &fixture_skip_b_l0_auth());
        assert!(r0 == FIXTURE_BOTTOM_ROOT1, 0);
    }

    #[test]
    fun test_fixture_skip_top_leaf1_path_matches_root() {
        // skip.ops[1].l1: top layer, leaf = tree_idx = 1, message = bottomRoot1.
        assert!(merkle_root(1, 0, 1, H, FIXTURE_LEAF_L1_T0_1, &fixture_skip_b_l1_auth()) == FIXTURE_ROOT, 0);
        // Top leaves 0 and 1 are siblings: each appears at level 0 of the other's path.
        assert!(*vector::borrow(&fixture_op0_l1_auth(), 0) == FIXTURE_LEAF_L1_T0_1, 1);
        assert!(merkle_root(1, 0, 0, H, FIXTURE_LEAF_L1_T0_0, &fixture_op0_l1_auth()) == FIXTURE_ROOT, 2);
    }

    // ---- test-only key material. A WOTS+ key whose chain secrets are
    // sha2_256 of a tag; sibling nodes are either the real neighbour leaf
    // (level 0, `real_sibling`) or tagged pseudo-random values. Verification
    // only recomputes the root from leaf and path, so this is a valid tree.

    // Roots of the test trees below, precomputed with the same builder so the
    // end-to-end tests pay only for signing and verification. Each unit test
    // runs under the Sui computation cap; building three full trees per test
    // (67 chains x 15 steps per leaf) exceeds it. The four tests after the
    // builder re-derive each constant and keep them honest.
    #[test_only]
    const TEST_ROOT_L0: vector<u8> = x"8102b1f0ea0521f39e5bac857837377b2a558f69d7a23bb1ed8b00cb269d1230";
    #[test_only]
    const TEST_ROOT_L0_REAL_SIBLING: vector<u8> = x"7458cfb7feb13b65393b4734e1fda45ae38944ee0671d69fff1e9226533ffb2d";
    #[test_only]
    const TEST_TOP_ROOT: vector<u8> = x"c8e96fff1a1a8ddcc6986dd90e29eb4db49797754a77639e286e30c972e743fe";
    /// Top tree with real leaves 0 and 1 (shared root), so that subtrees 0
    /// and 1 can both be registered under one `root`.
    #[test_only]
    const TEST_TOP_ROOT_REAL_SIBLING: vector<u8> = x"e4517a96b5870d6b6579521569bbc1ff551e4a4bb312af75a3f909f74632a873";
    #[test_only]
    const TEST_REC_ROOT: vector<u8> = x"e4a62032a86107a4a4fb6bc5da99e18964a44c3f4a1d52d434751d37d6b597fd";

    #[test_only]
    const TEST_LEAF_L0_T0_0: vector<u8> = x"4ca392961a2a5bdc1bcbbb2afad8987a03fa6c3e0308524586bf69525c57daa3";
    #[test_only]
    const TEST_LEAF_L0_T0_1: vector<u8> = x"27715fda3382c6825d166f4e5b2da44389633f81c682f0233e49a070a527897e";
    #[test_only]
    const TEST_LEAF_L1_T0_0: vector<u8> = x"149e84344848aacab782728ca9248d382fdc0c68487d5570419459b2a5cb09fd";
    #[test_only]
    const TEST_LEAF_L1_T0_1: vector<u8> = x"5a5fc6328fee986270108c88ca0c69d74fc7b184507ee6e88a58cc0ff19c5a94";

    #[test]
    fun test_precomputed_leaves() {
        assert!(test_leaf(0, 0, 0) == TEST_LEAF_L0_T0_0, 0);
        assert!(test_leaf(0, 0, 1) == TEST_LEAF_L0_T0_1, 1);
    }
    #[test]
    fun test_precomputed_top_leaves() {
        assert!(test_leaf(1, 0, 0) == TEST_LEAF_L1_T0_0, 0);
        assert!(test_leaf(1, 0, 1) == TEST_LEAF_L1_T0_1, 1);
    }
    #[test]
    fun test_precomputed_root_l0() { assert!(test_root(0, 0, 0, H, false) == TEST_ROOT_L0, 0); }
    #[test]
    fun test_precomputed_root_l0_real_sibling() { assert!(test_root(0, 0, 1, H, true) == TEST_ROOT_L0_REAL_SIBLING, 0); }
    #[test]
    fun test_precomputed_top_root() { assert!(test_root(1, 0, 0, H, false) == TEST_TOP_ROOT, 0); }
    #[test]
    fun test_precomputed_top_root_real_sibling() {
        assert!(test_root(1, 0, 0, H, true) == TEST_TOP_ROOT_REAL_SIBLING, 0);
        assert!(test_root(1, 0, 1, H, true) == TEST_TOP_ROOT_REAL_SIBLING, 1);
    }
    #[test]
    fun test_precomputed_rec_root() { assert!(test_root(LAYER_REC, 0, 0, REC_H, false) == TEST_REC_ROOT, 0); }

    /// State transition of `execute_transfer` for an operation at `idx` whose
    /// bottom-layer root is already known to be `r0`: index discipline,
    /// subtree settlement (cache lookup or top-layer registration) and
    /// counter update, in that order. Skipping the bottom-layer WOTS+
    /// verification is what keeps the index-discipline tests under budget.
    #[test_only]
    fun test_apply(
        acct: &mut CchsAccount,
        idx: u64,
        r0: vector<u8>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
    ) {
        let account = object::uid_to_address(&acct.id);
        check_index(acct, idx);
        settle_subtree(acct, account, idx, r0, has_l1, &l1_wots, &l1_auth);
        advance(acct, idx);
    }

    #[test_only]
    fun test_sk(layer: u8, tree_idx: u64, leaf_idx: u64, c: u64): vector<u8> {
        let mut buf = b"AEGIS_TEST_SK";
        vector::push_back(&mut buf, layer);
        vector::append(&mut buf, be64(tree_idx));
        vector::append(&mut buf, be64(leaf_idx));
        vector::append(&mut buf, be64(c));
        hash::sha2_256(buf)
    }

    #[test_only]
    fun test_chain(layer: u8, tree_idx: u64, leaf_idx: u64, c: u64, x: vector<u8>, from: u8, to: u8): vector<u8> {
        let mut x = x;
        let mut s = from;
        while (s < to) {
            let mut input = adrs(layer, tree_idx, 0x00, leaf_idx, (c as u8), s);
            vector::append(&mut input, x);
            x = hash::sha2_256(input);
            s = s + 1;
        };
        x
    }

    #[test_only]
    fun test_leaf(layer: u8, tree_idx: u64, leaf_idx: u64): vector<u8> {
        let mut buf = adrs(layer, tree_idx, 0x01, leaf_idx, 0, 0);
        let mut c: u64 = 0;
        while (c < LEN) {
            vector::append(&mut buf, test_chain(layer, tree_idx, leaf_idx, c, test_sk(layer, tree_idx, leaf_idx, c), 0, 15));
            c = c + 1;
        };
        hash::sha2_256(buf)
    }

    #[test_only]
    fun test_sign(layer: u8, tree_idx: u64, leaf_idx: u64, m: &vector<u8>): vector<vector<u8>> {
        let d = digits(m);
        let mut sig = vector::empty<vector<u8>>();
        let mut c: u64 = 0;
        while (c < LEN) {
            let dc = *vector::borrow(&d, c);
            vector::push_back(&mut sig, test_chain(layer, tree_idx, leaf_idx, c, test_sk(layer, tree_idx, leaf_idx, c), 0, dc));
            c = c + 1;
        };
        sig
    }

    #[test_only]
    fun test_auth(layer: u8, tree_idx: u64, leaf_idx: u64, height: u64, real_sibling: bool): vector<vector<u8>> {
        let mut auth = vector::empty<vector<u8>>();
        let mut k: u64 = 0;
        while (k < height) {
            let node_idx = (leaf_idx >> (k as u8)) ^ 1;
            let sib = if (k == 0 && real_sibling) {
                // Leaves 0 and 1 of bottom tree 0 and of the top tree are
                // precomputed (verified by test_precomputed_leaves and
                // test_precomputed_top_leaves); anything else is built here.
                if (layer == 0 && tree_idx == 0 && node_idx == 0) TEST_LEAF_L0_T0_0
                else if (layer == 0 && tree_idx == 0 && node_idx == 1) TEST_LEAF_L0_T0_1
                else if (layer == 1 && tree_idx == 0 && node_idx == 0) TEST_LEAF_L1_T0_0
                else if (layer == 1 && tree_idx == 0 && node_idx == 1) TEST_LEAF_L1_T0_1
                else test_leaf(layer, tree_idx, node_idx)
            } else {
                let mut buf = b"AEGIS_TEST_NODE";
                vector::push_back(&mut buf, layer);
                vector::append(&mut buf, be64(tree_idx));
                vector::append(&mut buf, be64(node_idx));
                vector::push_back(&mut buf, (k as u8));
                hash::sha2_256(buf)
            };
            vector::push_back(&mut auth, sib);
            k = k + 1;
        };
        auth
    }

    #[test_only]
    fun test_root(layer: u8, tree_idx: u64, leaf_idx: u64, height: u64, real_sibling: bool): vector<u8> {
        merkle_root(layer, tree_idx, leaf_idx, height, test_leaf(layer, tree_idx, leaf_idx), &test_auth(layer, tree_idx, leaf_idx, height, real_sibling))
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

    /// skip.ops[0].l0.auth: leaf 5 of bottom tree 0.
    #[test_only]
    fun fixture_skip_a_l0_auth(): vector<vector<u8>> {
        vector[
            x"ad0be2267f130edd718c2502d8a04a020fcf7f7992e1557221e90d5fb3a94f5c",
            x"4c3ee8c40cd04143cbcceb0d72bfbfd4b943b07c9d9f1ba31673f6d6a3ba286c",
            x"ec639785d2ca72899600bbb127058b55d34fae0d08f4fcf12f73d2a7857bdcc7",
            x"5e72add3cb130b8fbea418d1f3b2a2a506feba02be382c6a102a047e202ee7e6",
            x"575335c4000842b2c80d0584c6509c92362474725f11085c3b3e85e3f6ef3b62",
            x"9a6609a09286b8d0102b29d242a358bd3f100be36fc89c1b3e2f7c6f0698707b",
            x"1bce46fe9ddd267125035bff246c715b3702d09d573d98f4143770cd8c5303ff",
            x"1521e03b61b9cf159eca6c3fe03ae55a686d619e6a160f502e95e0f0d4c95b01",
            x"b3551ec61ae4e21230b7ae9a4f408b9198ba80698773d5e202af0325c4b2b6cf",
            x"166f57c72b5c66002859c7b910151f2b5b8c51936f7215f16e7381796726bce8",
        ]
    }

    /// skip.ops[1].l0.wots: WOTS+ signature at leaf 0 of bottom tree 1.
    #[test_only]
    fun fixture_skip_b_l0_wots(): vector<vector<u8>> {
        vector[
            x"57b7ec52d1ef4291fb8998bc287e5b3438526a43c1308a2009a227525fd87e6a",
            x"f7f932bf972a8255d8323ff7fa4c3b02b1d655f77ec8abbc471a91b2adce104e",
            x"f33ae95f74d78039a95ad84472ccca75f21a70696ed69d30f96572a6fe8cc67c",
            x"9c3f5176c0bcd9dd8d31d48614b540f313e24f0c6574eb4225b1c6e015442cbc",
            x"8a883a46abb6d80e4759325bada067b3d5cef8242636fad3402ac90fdbe2086d",
            x"0bd3c874eeb17012ea4ac7dad1ccff2b716e48fa376ffdce0ed22742b3ecf515",
            x"720d79cf7dfaf222f525ad9158ff2bdf6d690475429efd468160298c541eae6a",
            x"7ed03c41cae8eed8d2664698cd67cf60d2cb049d1739fe23d6e2644ef0813bc4",
            x"4215f1474f877aac1f4c208922ee6e42fa4487a87cc90d3ee27cd8229533e1e4",
            x"dc23219ae9b97c3aa44eb1ca02aa8d9cdaa8bafbac405f74c8f56a9c56e48e0d",
            x"bdc00166b3b374cb5546f6832b3f705e2e179f04594462a13ffef1376ca3d94a",
            x"4f5b477d2b455c79bf99e4132453cb4ad3e98ef8ae0c0176e1c5d0212494db5c",
            x"23ac2b12ddfc36cc5fcd17ed4f70ca586660c635d58b47d93cf94cebd7a2e2be",
            x"4694f309063d55b1b67c9dd4489a74424626d562f82fab4284be754633077c76",
            x"ec9a2ddf304f249c1a64f1aec241847ab9754449e42d66de8df378a0dbd597a8",
            x"6fe0b721ca0cfdc7b637b9324c79f715004696c9883bd2e1017d1cbb6ef4a9f7",
            x"3f452a3a085ddc2973c3cf0c13d841af3c7ae3f830898976674c0a2c2d156277",
            x"7f1e6fccb6e4b0b7159cc1c87188c81a30f702f07f48837e7ae82c188ed4c419",
            x"0ec5b6eaa220a7505b1a46c0e9ab2b403dd85920a5af3b33c0589ae8eb99d7fd",
            x"631fdef6f18c982f78c8e0e0acd9b194e35db78410f8b5f904a1084ed8edaf0d",
            x"8830cc1bde368ba685b68a37eb0a1abe823682b024afabbc2dfd3f994ecf361c",
            x"f03e32b7b0881c8e52d197872d26df90c9339db86c5a46630c785549f4310c3c",
            x"4ca50aeb342ff6fbdbf3c373f9f5863a71304ce00a2ff0f38e2dede5d467a3cd",
            x"8ae97e8f50e4ad7d701a8df857cfe2a5ce82a57512d82ebe22cb2cd7d5b7d0ca",
            x"e57c4ec63126f3375239d23ca23cdbf4c3a3f06293e2f7fe63f0d667cb764d55",
            x"a69b53095380c4b13b1cacb8f6e7cf75794ef0fab8afeabf9c73fd81930efef2",
            x"6873278febfa9a151ff3927caf79d149382c95a16a0cf5e3d16f57bf0073ced2",
            x"ebb6770415ab9061eb82b7ae2214a1c16509a2b4f32ede0be98d859d2ce4a771",
            x"56444374ec5057f6b2cca5227e7c75865f4e69f320a905879ec3bc2d51074d53",
            x"0bae1c1a34913b57798cd2f5a846fb51b0f9d1c0439d5b252b5a1bad2295f85e",
            x"89f57d5ca917d5d7ced7b406e73373f07232c1a3cc99d104999ab970090bc28a",
            x"34e367a3cfe3aeaa2d7d5315684df8a35a1ee1d29df21722da9d174f6523fb89",
            x"f54a3b6bddbf74d553e7ed10501eaddb5317ade15e41de3e1fcdbe648de7c416",
            x"545ad3900a4d8c75f44fde394991987ee8ec23298877cd75463b4f93916dfe8a",
            x"31c49d0fa1c0373cbfe9dc416a6849607743e7625a9e5b88bd4b9a807cfc35f0",
            x"7232ea5dcf7a309d0864162f92fd2dbd6dec7ce9e6aee501d8d73179c56bbdaa",
            x"f2a91c726c0ff490b6b9a203c376756c4510dc9b10df3c995289e88f6eacd1da",
            x"dfe430900fbe9bf4a6f8f84b9504396af25a40ee3f589d59f501a29d86ffd209",
            x"3ee8015807aaea074a8fab90d272b51a6d483f055d86c90d179ff7824af6f6b8",
            x"7e09f93955802100f53eb98b12f3dc8b73a3639f44d3be7978db0e7d854ef930",
            x"aa484709bc39b64264aff1a2b6ac0fd19f61651faf7611739064d5e58dfc64df",
            x"3475a674df456a03a48b170ceff6f519c79504ff79fa87dce3e571e2a15ba62a",
            x"7e0db3b75eb4ee740d7cd8f0f38af31438b7261ee8ba1d1e751871624f6883d5",
            x"5d6cd747a6ec2488023a0b2b3c9f0597a2d439bd978f0854e6a232898acc61de",
            x"e0193d4d25ed8d889aa99cf9e97581473218c4f7213a48fc13d38a8870d5e20d",
            x"d7a68b5851390386646c95af7fb1bc54e1cf3e2592b9a6f56d17b626df592a56",
            x"b8af0fabdbf4cf0625c1df252162e99d16cfaf3ae1ff9ca2f255cfe35fa416be",
            x"cf082bb9b1a1a24a1aef13b46e0a45c571088f56c1df4b603444137f1ea4ff6d",
            x"844830cfeca567fd6c504b2698723d85476e572c9d7ea4931946a92981d9e087",
            x"7c21df0a0c6b6cde34aae82b03a0350b3b05eb99e251837db1e7d7f42ba7f982",
            x"8ec0a407ada719e5bd6748478403813f87086a217a183955e5eb9b9218bae934",
            x"b540f4009d8c3f52a750f4536b0fd6c30a1ef8cfb154080fb1d32d9ebc94436c",
            x"36673dc9a3d54f4dbbc83bf90eba63703c124389cbdd1cd7050463b8af704223",
            x"9c5dc3de0a87c5d66c2b7f7e49b6dc7f04133efa4e92e8fe497a6eb7a9e01ee2",
            x"1b3f7b9a77754c7ced4181926688b12844715efd8baab7442dbe7d93c1d7c5a0",
            x"0fb8972d343fc7acde999ebdac1c7e98456501fd61f1931393af8f6d21437315",
            x"6b0544da6ee18f728a1124f255b718bc863a9964ef6d825f218eedebfba980f8",
            x"4dd7744076192dd3700c35966b353d7d34c239e771c7eafa2e570fdf3ea0834c",
            x"3ca7d2f3d2d6f8401aa01abe50cd78c6e316fb836fc48365999556f6b8a1689f",
            x"db885d9c7b9c8561fc84904ca39499f97744893c5b8db1b2870da42464fd0d36",
            x"ff3aac4b8c73665b7ba8611facf9c77d4590b6cd28ed2c0d5c190db71cf6e639",
            x"75497f5028a2da31488134e7045598d73fbbe21bb7bf216b00afa8d4ddc5495b",
            x"a43b7237eefdd49c3b9d02142c3fd283163d15b6285fcc81a46a2c26848d7604",
            x"ac3aae587204abaae95707c979137aa201b7e8d1c3f46fc38413568f6d25cbf8",
            x"b49278022e6519c3a78383a2b0925baae3eb42ac2e89aad97339a3840f586ea2",
            x"f57c8a748f1cccb347929bf8fa00f6943c1fcc7a54a8f0dbabd4287d66329fc7",
            x"dabb3ef753bb1672f8d70c8dd32943ab6876a2289a8b7540b94e513b3f8880fc",
        ]
    }

    /// skip.ops[1].l0.auth: leaf 0 of bottom tree 1.
    #[test_only]
    fun fixture_skip_b_l0_auth(): vector<vector<u8>> {
        vector[
            x"b86fcfba6f0ed1ba32daf8c39230e0e5d3dbc15537fdb9ac2f85b7ca41f3e1fa",
            x"63a3d5c8aa5de54b309c77aff8e8caf37377b1fec8fa992a8baa88d8922bd24a",
            x"e37f4a6311831aa366f8a80e0e45789e6fcdf5f853c4872397e0f64b486aa7cd",
            x"69a9eeaf708b93f9ada6d7dfd4c0a56bf7c1fba2936d1841058659aa80f2b43d",
            x"430efe8a42661c581247b92350e72de907220a8e76ac2f335345454cceef78a0",
            x"cb002ac83793090a8ea29a7507dcc0c4078599df025b7b4aa5d7d11d207b1369",
            x"504df9a0926dfb7929a12b7b2900c0a2d3864f389c54b776b6b3040e6f1912af",
            x"d142772e369fe9f28349414cd4c7cb4f2ea37328723d9e3327ca7b8b4a204b75",
            x"11cb7190b9b45ace52dd42312d48355c33f24168901d739e3f96b962215689d7",
            x"d8f594575be5f6e278f809c79d9bd69c6eb5bfd02f1e4bd99cf4f613a7e7a631",
        ]
    }

    /// skip.ops[1].l1.auth: top leaf 1. Levels 1..9 are shared with
    /// ops[0].l1.auth (top leaves 0 and 1 are siblings); level 0 is top leaf 0.
    #[test_only]
    fun fixture_skip_b_l1_auth(): vector<vector<u8>> {
        let mut auth = fixture_op0_l1_auth();
        *vector::borrow_mut(&mut auth, 0) = FIXTURE_LEAF_L1_T0_0;
        auth
    }
}
