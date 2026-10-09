/// Aegis CCHS account on Aptos (CCHS-S-20).
///
/// Hash-only post-quantum account authorization. Every operation is a WOTS+
/// signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of
/// height 10 + 10 (2^20 signatures). The top-layer proof for each bottom
/// subtree is verified once and cached; later signatures in that subtree
/// carry only the bottom layer.
///
/// No elliptic-curve key is in the authorization path. The funds live in a
/// resource account whose authentication key is zeroed by the framework at
/// creation (`account::create_resource_account`), and whose
/// `SignerCapability` is held inside the `CchsAccount` resource stored at
/// that same address. `execute_transfer*` takes no signer at all: any payer
/// may submit it, and the only gate is the CCHS signature. The creator's
/// key is used exactly once, in `create`, to pick the resource address.
///
/// Immutability requirement: this module must be published with
/// `upgrade_policy = "immutable"` (set in Move.toml). An upgradable module
/// would give the publisher's key the power to replace this code and take
/// the funds, which would reintroduce an elliptic-curve key into the trust
/// path. See ../README.md for the publish command and deployment models.
///
/// Byte-exact with `evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`
/// for ADRS, chain steps, leaf compression and Merkle nodes. Only the
/// message digest differs per chain (see `digest`). Spec: ../../CCHS.spec.md
module aegis::aegis_account {
    use std::bcs;
    use std::error;
    use std::hash;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_std::type_info;
    use aptos_framework::account::{Self, SignerCapability};
    use aptos_framework::aptos_account;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, Object};
    #[test_only]
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    #[test_only]
    use aptos_framework::coin;

    // ------------------------------------------------------------ params
    const LEN: u64 = 67;          // 64 message chains + 3 checksum chains
    const H: u64 = 10;            // tree height per layer
    const REC_H: u64 = 8;         // recovery tree height
    const CAPACITY: u64 = 1048576; // 2^(2*H)
    const REC_CAPACITY: u64 = 256; // 2^REC_H
    const LAYER_REC: u8 = 0xFF;

    /// Resource-account seed prefix: seed = SEED_PREFIX || root.
    const SEED_PREFIX: vector<u8> = b"AEGIS_CCHS_V1";
    /// Asset-id kind tags bound into the digest.
    const ASSET_KIND_COIN: u8 = 0x00;
    const ASSET_KIND_FA: u8 = 0x01;

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
    const E_INDEX_USED: u64 = 10;

    // ------------------------------------------------------------ state
    /// Stored under the resource account's own address. That address is the
    /// CCHS account address bound into every digest.
    struct CchsAccount has key {
        /// Top-layer tree root. Rotatable only via `recover`.
        root: vector<u8>,
        /// Recovery tree root (single layer, height 8).
        rec_root: vector<u8>,
        /// Public seed of the current key tree (16 bytes, in every ADRS).
        /// Rotated together with the roots by `recover`.
        seed: vector<u8>,
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
        /// The only way to produce a signer for the resource account. Never
        /// leaves this module; used only after a CCHS signature verified.
        signer_cap: SignerCapability,
        /// Address whose signer picked the resource address in `create`.
        /// Informational; it has no authority after creation.
        creator: address,
    }

    // ------------------------------------------------------------ events
    #[event]
    struct Created has drop, store { account: address, creator: address, root: vector<u8>, rec_root: vector<u8>, seed: vector<u8> }
    #[event]
    struct Executed has drop, store { account: address, idx: u64, asset: vector<u8>, recipient: address, amount: u64 }
    #[event]
    struct SubtreeCached has drop, store { account: address, epoch: u64, tree_idx: u64, subtree_root: vector<u8> }
    #[event]
    struct Recovered has drop, store { account: address, new_epoch: u64, new_root: vector<u8>, new_rec_root: vector<u8>, new_seed: vector<u8> }

    // ============================================================ create

    /// Create a CCHS account. A resource account is derived from
    /// `creator` and `seed = "AEGIS_CCHS_V1" || root`
    /// (`account::create_resource_account`), its authentication key is
    /// zeroed by the framework, and the returned `SignerCapability` is
    /// stored inside the `CchsAccount` resource published at the resource
    /// address. Funds sent to that address are spendable only through
    /// `execute_transfer*`. `creator` may be any signer, including a relayer;
    /// it keeps no authority. Use `derive_address` to predict the address.
    public entry fun create(creator: &signer, root: vector<u8>, rec_root: vector<u8>, seed: vector<u8>) {
        assert_root(&root);
        assert_root(&rec_root);
        assert_seed(&seed);
        let (res_signer, signer_cap) = account::create_resource_account(creator, resource_seed(&root));
        let addr = signer::address_of(&res_signer);
        assert!(!exists<CchsAccount>(addr), error::already_exists(E_ALREADY_INIT));
        let creator_addr = signer::address_of(creator);
        event::emit(Created { account: addr, creator: creator_addr, root, rec_root, seed });
        move_to(&res_signer, CchsAccount {
            root,
            rec_root,
            seed,
            epoch: 0,
            next_idx: 0,
            nonce: 0,
            rec_nonce: 0,
            cached_root: table::new<u128, vector<u8>>(),
            signer_cap,
            creator: creator_addr,
        });
    }

    /// Convenience: move `amount` of `CoinType` from `payer` into the CCHS
    /// account. Equivalent to `aptos_account::transfer_coins<CoinType>(payer,
    /// acct_addr, amount)`; any direct transfer to the address works too.
    public entry fun deposit<CoinType>(payer: &signer, acct_addr: address, amount: u64) {
        assert!(exists<CchsAccount>(acct_addr), error::not_found(E_NOT_INIT));
        aptos_account::transfer_coins<CoinType>(payer, acct_addr, amount);
    }

    // ============================================================ execute

    /// Transfer `amount` of `CoinType` (APT is `0x1::aptos_coin::AptosCoin`)
    /// from the CCHS account to `recipient`, authorized only by a CCHS
    /// signature on the transfer digest. No signer: anyone may submit.
    ///
    /// `idx` is the leaf index the signer chose. It must be `>= next_idx`;
    /// every lower leaf is abandoned forever (`next_idx` becomes `idx + 1`).
    /// Skipping is how a signer leaves behind a leaf whose signature was
    /// broadcast but never landed, or an entire subtree whose keys it no
    /// longer trusts. Only the signer can skip, because `idx` is bound into
    /// the digest.
    ///
    /// `l0_*` is the bottom-layer WOTS+ signature (67 x 32 bytes) and auth
    /// path (10 x 32 bytes) for leaf `idx`. `has_l1` / `l1_*` carry the
    /// top-layer proof: required when the subtree of `idx` is not yet
    /// registered for the current epoch, ignored (not rejected) when it
    /// already is, so a transaction prepared before another registration
    /// landed still succeeds.
    public entry fun execute_transfer<CoinType>(
        acct_addr: address,
        recipient: address,
        amount: u64,
        idx: u64,
        l0_wots: vector<vector<u8>>,
        l0_auth: vector<vector<u8>>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        let asset = coin_asset_id<CoinType>();
        let res_signer = authorize(
            acct_addr, &asset, recipient, amount, idx, &l0_wots, &l0_auth, has_l1, &l1_wots, &l1_auth,
        );
        aptos_account::transfer_coins<CoinType>(&res_signer, recipient, amount);
        event::emit(Executed { account: acct_addr, idx, asset, recipient, amount });
    }

    /// Same as `execute_transfer`, for a fungible asset identified by its
    /// `Metadata` object (tokens that exist only as fungible assets).
    public entry fun execute_transfer_fa(
        acct_addr: address,
        metadata: Object<Metadata>,
        recipient: address,
        amount: u64,
        idx: u64,
        l0_wots: vector<vector<u8>>,
        l0_auth: vector<vector<u8>>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        let asset = fa_asset_id(object::object_address(&metadata));
        let res_signer = authorize(
            acct_addr, &asset, recipient, amount, idx, &l0_wots, &l0_auth, has_l1, &l1_wots, &l1_auth,
        );
        aptos_account::transfer_fungible_assets(&res_signer, metadata, recipient, amount);
        event::emit(Executed { account: acct_addr, idx, asset, recipient, amount });
    }

    /// Verify the CCHS signature for the signer-chosen leaf `idx`, advance
    /// the counters, and return a signer for the resource account. All state
    /// effects happen here, before any asset moves.
    fun authorize(
        acct_addr: address,
        asset: &vector<u8>,
        recipient: address,
        amount: u64,
        idx: u64,
        l0_wots: &vector<vector<u8>>,
        l0_auth: &vector<vector<u8>>,
        has_l1: bool,
        l1_wots: &vector<vector<u8>>,
        l1_auth: &vector<vector<u8>>,
    ): signer acquires CchsAccount {
        assert!(exists<CchsAccount>(acct_addr), error::not_found(E_NOT_INIT));
        let acct = borrow_global_mut<CchsAccount>(acct_addr);
        check_index(acct, idx);

        let m = digest(acct_addr, acct.nonce, idx, *asset, recipient, amount);
        let r0 = verify_bottom_layer(&acct.seed, idx, &m, l0_wots, l0_auth);
        settle_subtree(acct, acct_addr, idx, r0, has_l1, l1_wots, l1_auth);

        // effects before interaction
        advance(acct, idx);

        account::create_signer_with_capability(&acct.signer_cap)
    }

    // ============================================================ recovery

    /// Rotate the public key (`root`, `rec_root`, `seed`), authorized by the
    /// recovery tree under the current seed. Resets `next_idx` and bumps
    /// `epoch` (logically clearing the cache). Callable by anyone holding a
    /// valid recovery signature. The account address does not change (it was
    /// fixed by the original root).
    public entry fun recover(
        acct_addr: address,
        new_root: vector<u8>,
        new_rec_root: vector<u8>,
        new_seed: vector<u8>,
        wots: vector<vector<u8>>,
        auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        assert!(exists<CchsAccount>(acct_addr), error::not_found(E_NOT_INIT));
        assert_root(&new_root);
        assert_root(&new_rec_root);
        assert_seed(&new_seed);
        let acct = borrow_global_mut<CchsAccount>(acct_addr);

        let rn = acct.rec_nonce;
        assert!(rn < REC_CAPACITY, error::out_of_range(E_EXHAUSTED));

        let m = recovery_digest(acct_addr, rn, &new_root, &new_rec_root, &new_seed);
        let r = verify_layer(&acct.seed, LAYER_REC, 0, rn, REC_H, &m, &wots, &auth);
        assert!(r == acct.rec_root, error::permission_denied(E_BAD_RECOVERY));

        acct.root = new_root;
        acct.rec_root = new_rec_root;
        acct.seed = new_seed;
        acct.next_idx = 0;
        acct.epoch = acct.epoch + 1;
        acct.rec_nonce = rn + 1;
        event::emit(Recovered {
            account: acct_addr,
            new_epoch: acct.epoch,
            new_root: acct.root,
            new_rec_root: acct.rec_root,
            new_seed: acct.seed,
        });
    }

    // ============================================================ views

    /// Address the CCHS account will get when `creator` calls `create` with `root`.
    #[view]
    public fun derive_address(creator: address, root: vector<u8>): address {
        account::create_resource_address(&creator, resource_seed(&root))
    }

    /// Asset id for `Coin<CoinType>`: sha2_256(0x00 || utf8(type_name<CoinType>())).
    /// For APT the name is "0x1::aptos_coin::AptosCoin".
    #[view]
    public fun coin_asset_id<CoinType>(): vector<u8> {
        let buf = vector::singleton(ASSET_KIND_COIN);
        vector::append(&mut buf, *string::bytes(&type_info::type_name<CoinType>()));
        hash::sha2_256(buf)
    }

    /// Asset id for a fungible asset: sha2_256(0x01 || bcs(metadata_address)).
    #[view]
    public fun fa_asset_id(metadata: address): vector<u8> {
        let buf = vector::singleton(ASSET_KIND_FA);
        vector::append(&mut buf, bcs::to_bytes(&metadata));
        hash::sha2_256(buf)
    }

    /// Digest the client must sign for an `execute_transfer<CoinType>` at
    /// leaf `idx` (`idx >= next_idx`) with the current nonce.
    #[view]
    public fun digest_at<CoinType>(acct_addr: address, idx: u64, recipient: address, amount: u64): vector<u8> acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        digest(acct_addr, acct.nonce, idx, coin_asset_id<CoinType>(), recipient, amount)
    }

    /// Digest for an `execute_transfer<CoinType>` at `next_idx`.
    #[view]
    public fun next_digest<CoinType>(acct_addr: address, recipient: address, amount: u64): vector<u8> acquires CchsAccount {
        digest_at<CoinType>(acct_addr, borrow_global<CchsAccount>(acct_addr).next_idx, recipient, amount)
    }

    /// Digest the client must sign for an `execute_transfer_fa` at leaf `idx`.
    #[view]
    public fun digest_at_fa(acct_addr: address, idx: u64, metadata: address, recipient: address, amount: u64): vector<u8> acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        digest(acct_addr, acct.nonce, idx, fa_asset_id(metadata), recipient, amount)
    }

    /// Digest for an `execute_transfer_fa` at `next_idx`.
    #[view]
    public fun next_digest_fa(acct_addr: address, metadata: address, recipient: address, amount: u64): vector<u8> acquires CchsAccount {
        digest_at_fa(acct_addr, borrow_global<CchsAccount>(acct_addr).next_idx, metadata, recipient, amount)
    }

    /// Digest the client must sign for the next `recover`.
    #[view]
    public fun next_recovery_digest(acct_addr: address, new_root: vector<u8>, new_rec_root: vector<u8>, new_seed: vector<u8>): vector<u8> acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        recovery_digest(acct_addr, acct.rec_nonce, &new_root, &new_rec_root, &new_seed)
    }

    /// Whether an `execute_transfer*` at leaf `idx` must include the top-layer proof.
    #[view]
    public fun needs_top_layer_at(acct_addr: address, idx: u64): bool acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        !table::contains(&acct.cached_root, cache_key(acct.epoch, idx >> 10))
    }

    /// Whether an `execute_transfer*` at `next_idx` must include the top-layer proof.
    #[view]
    public fun needs_top_layer(acct_addr: address): bool acquires CchsAccount {
        needs_top_layer_at(acct_addr, borrow_global<CchsAccount>(acct_addr).next_idx)
    }

    #[view]
    public fun root(acct_addr: address): vector<u8> acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).root }
    #[view]
    public fun rec_root(acct_addr: address): vector<u8> acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).rec_root }
    /// 16-byte public seed of the current key tree.
    #[view]
    public fun seed(acct_addr: address): vector<u8> acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).seed }
    #[view]
    public fun epoch(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).epoch }
    #[view]
    public fun next_idx(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).next_idx }
    #[view]
    public fun nonce(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).nonce }
    #[view]
    public fun rec_nonce(acct_addr: address): u64 acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).rec_nonce }
    #[view]
    public fun creator_of(acct_addr: address): address acquires CchsAccount { borrow_global<CchsAccount>(acct_addr).creator }

    // ============================================================ internals

    fun assert_root(r: &vector<u8>) {
        assert!(vector::length(r) == 32, error::invalid_argument(E_BAD_LENGTH));
        assert!(*r != x"0000000000000000000000000000000000000000000000000000000000000000", error::invalid_argument(E_ZERO_ROOT));
    }

    /// seed = "AEGIS_CCHS_V1" || root (13 + 32 bytes). The resource address is
    /// sha3_256(bcs(creator) || seed || 0xFF), per `account::create_resource_address`.
    fun resource_seed(root: &vector<u8>): vector<u8> {
        let seed = SEED_PREFIX;
        vector::append(&mut seed, *root);
        seed
    }

    fun assert_seed(s: &vector<u8>) {
        assert!(vector::length(s) == 16, error::invalid_argument(E_BAD_LENGTH));
    }

    fun cache_key(epoch: u64, tree_idx: u64): u128 {
        ((epoch as u128) << 64) | (tree_idx as u128)
    }

    /// M = sha2_256("AEGIS_CCHS_V1" || "aptos" || bcs(account) || nonce(8 BE) || idx(8 BE)
    ///              || sha2_256(asset || bcs(recipient) || amount(8 BE)))
    /// `account` is the resource account address; `asset` is `coin_asset_id` or `fa_asset_id`.
    fun digest(account: address, nonce: u64, idx: u64, asset: vector<u8>, recipient: address, amount: u64): vector<u8> {
        let action = asset;
        vector::append(&mut action, bcs::to_bytes(&recipient));
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
    ///                  || new_root || new_rec_root || new_seed(16))
    fun recovery_digest(account: address, rec_nonce: u64, new_root: &vector<u8>, new_rec_root: &vector<u8>, new_seed: &vector<u8>): vector<u8> {
        let buf = b"AEGIS_CCHS_RECOVER_V1";
        vector::append(&mut buf, b"aptos");
        vector::append(&mut buf, bcs::to_bytes(&account));
        vector::append(&mut buf, be64(rec_nonce));
        vector::append(&mut buf, *new_root);
        vector::append(&mut buf, *new_rec_root);
        vector::append(&mut buf, *new_seed);
        hash::sha2_256(buf)
    }

    /// Index discipline: the signer-chosen leaf must not be behind `next_idx`
    /// and must exist in the 2^20 index space.
    fun check_index(acct: &CchsAccount, idx: u64) {
        assert!(idx >= acct.next_idx, error::invalid_argument(E_INDEX_USED));
        assert!(idx < CAPACITY, error::out_of_range(E_EXHAUSTED));
    }

    /// Counter update after a verified operation at `idx`: every leaf below
    /// `idx` is abandoned, and the nonce moves on.
    fun advance(acct: &mut CchsAccount, idx: u64) {
        acct.next_idx = idx + 1;
        acct.nonce = acct.nonce + 1;
    }

    /// Bottom-layer root recomputed from the WOTS+ signature on `m` at leaf `idx`.
    fun verify_bottom_layer(
        seed: &vector<u8>,
        idx: u64,
        m: &vector<u8>,
        l0_wots: &vector<vector<u8>>,
        l0_auth: &vector<vector<u8>>,
    ): vector<u8> {
        verify_layer(seed, 0, idx >> 10, idx & 1023, H, m, l0_wots, l0_auth)
    }

    /// Given the recomputed bottom root `r0` of the subtree of `idx`: if the
    /// subtree is registered for this epoch, require equality with the cached
    /// root and ignore any supplied top layer; otherwise require the top
    /// layer, verify it against `root` and register `r0`. Aborts on mismatch.
    fun settle_subtree(
        acct: &mut CchsAccount,
        addr: address,
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
            assert!(*cached == r0, error::permission_denied(E_BAD_SUBTREE_ROOT));
            return
        };
        assert!(has_l1, error::invalid_argument(E_MISSING_TOP_LAYER));
        // Top layer: tree 0, leaf = tree_idx, message = r0.
        let r1 = verify_layer(&acct.seed, 1, 0, tree_idx, H, &r0, l1_wots, l1_auth);
        assert!(r1 == acct.root, error::permission_denied(E_BAD_TOP_ROOT));
        table::add(&mut acct.cached_root, key, r0);
        event::emit(SubtreeCached { account: addr, epoch: acct.epoch, tree_idx, subtree_root: r0 });
    }

    /// Recompute the root of tree (`layer`, `tree_idx`) of height `height`
    /// from a WOTS+ signature on `m` at `leaf_idx` and the auth path.
    /// Pure; byte-exact with `AegisCCHS._layerRoot`.
    public fun verify_layer(
        seed: &vector<u8>,
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

        let d = digits(m);

        // Leaf: sha2_256(adrs_leaf || pk_0 || ... || pk_66)
        assert_seed(seed);
        let leaf_buf = adrs(seed, layer, tree_idx, 0x01, leaf_idx, 0, 0);
        let c = 0;
        while (c < LEN) {
            let x = *vector::borrow(wots, c);
            assert!(vector::length(&x) == 32, error::invalid_argument(E_BAD_LENGTH));
            let s = *vector::borrow(&d, c);
            while (s < 15) {
                let input = adrs(seed, layer, tree_idx, 0x00, leaf_idx, (c as u8), s);
                vector::append(&mut input, x);
                x = hash::sha2_256(input);
                s = s + 1;
            };
            vector::append(&mut leaf_buf, x);
            c = c + 1;
        };
        merkle_root(seed, layer, tree_idx, leaf_idx, height, hash::sha2_256(leaf_buf), auth)
    }

    /// Auth path, leaf -> root: node_k = sha2_256(adrs(seed, layer, tree, 0x02, pos >> 1, k, 0) || left || right).
    public fun merkle_root(
        seed: &vector<u8>,
        layer: u8,
        tree_idx: u64,
        leaf_idx: u64,
        height: u64,
        node: vector<u8>,
        auth: &vector<vector<u8>>,
    ): vector<u8> {
        assert!(vector::length(auth) == height, error::invalid_argument(E_BAD_LENGTH));
        let pos = leaf_idx;
        let k = 0;
        while (k < height) {
            let sib = *vector::borrow(auth, k);
            assert!(vector::length(&sib) == 32, error::invalid_argument(E_BAD_LENGTH));
            let input = adrs(seed, layer, tree_idx, 0x02, pos >> 1, (k as u8), 0);
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

    /// ADRS = layer(1) || tree_idx(8 BE) || type(1) || leaf_idx(4 BE) || chain_idx(1) || step(1) || pk_seed(16)
    /// `seed` is the 16-byte public seed of the key tree: it makes every hash
    /// call of one tree a different function from the same position in any
    /// other tree (spec 2.2, 5.5).
    public fun adrs(seed: &vector<u8>, layer: u8, tree_idx: u64, typ: u8, leaf_idx: u64, chain_idx: u8, step: u8): vector<u8> {
        let a = vector::empty<u8>();
        vector::push_back(&mut a, layer);
        vector::append(&mut a, be64(tree_idx));
        vector::push_back(&mut a, typ);
        vector::append(&mut a, be32(leaf_idx));
        vector::push_back(&mut a, chain_idx);
        vector::push_back(&mut a, step);
        vector::append(&mut a, *seed);
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
    // Digest / address vectors were recomputed independently with Node's
    // crypto module (sha256, sha3-256) from the byte layouts documented above.

    #[test]
    fun test_adrs_layout() {
        let seed = x"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        let a = adrs(&seed, 0x01, 0x0102030405060708, 0x02, 0x0a0b0c0d, 0x21, 0x0e);
        assert!(a == x"010102030405060708020a0b0c0d210ea0a1a2a3a4a5a6a7a8a9aaabacadaeaf", 0);
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
        let r0 = verify_layer(&FIXTURE_SEED, 0, 0, 1, 10, &m, &fixture_op1_l0_wots(), &fixture_op1_l0_auth());
        assert!(r0 == FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_layer0_fixture_op1_under_other_seed_mismatches() {
        // The same signature hashed under a different public seed reaches a
        // different root: the seed separates every tree's hash functions.
        let m = x"7c06dfcdc83e3f42a32ee106be945deee21183c9a8563a2eab8450cbc7f1cede";
        let r0 = verify_layer(&TEST_SEED, 0, 0, 1, 10, &m, &fixture_op1_l0_wots(), &fixture_op1_l0_auth());
        assert!(r0 != FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_layer1_fixture_op0_matches_root() {
        // ops[0].l1: top layer, tree 0, leaf = tree_idx = 0, message = bottomRoot0.
        let r0 = FIXTURE_BOTTOM_ROOT0;
        let r1 = verify_layer(&FIXTURE_SEED, 1, 0, 0, 10, &r0, &fixture_op0_l1_wots(), &fixture_op0_l1_auth());
        assert!(r1 == FIXTURE_ROOT, 0);
    }

    #[test]
    #[expected_failure]
    fun test_layer0_tampered_chain_fails() {
        let m = x"7c06dfcdc83e3f42a32ee106be945deee21183c9a8563a2eab8450cbc7f1cede";
        let wots = fixture_op1_l0_wots();
        *vector::borrow_mut(&mut wots, 3) = x"0000000000000000000000000000000000000000000000000000000000000000";
        let r0 = verify_layer(&FIXTURE_SEED, 0, 0, 1, 10, &m, &wots, &fixture_op1_l0_auth());
        assert!(r0 == FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_derive_address_vector() {
        // sha3_256(bcs(0xa11ce) || "AEGIS_CCHS_V1" || 0x11*32 || 0xff)
        let root = x"1111111111111111111111111111111111111111111111111111111111111111";
        assert!(resource_seed(&root) == x"41454749535f434348535f56311111111111111111111111111111111111111111111111111111111111111111", 0);
        assert!(derive_address(@0xa11ce, root) == @0x6a3877bd99d7507ed6dbd0917238ee7b33135d32499d529dc99a1f29af48ca33, 1);
    }

    #[test]
    fun test_asset_ids_and_digest_vectors() {
        assert!(*string::bytes(&type_info::type_name<AptosCoin>()) == b"0x1::aptos_coin::AptosCoin", 0);
        let apt = coin_asset_id<AptosCoin>();
        assert!(apt == x"b4caa83e4235ecb06414be3480b265dd67e10ab51736679fdfd62a64807f4112", 1);
        assert!(fa_asset_id(@0xa) == x"14fe83f39cd306eceb684d801a955bb5092ac3484ac7e3ff585809e19be6fa97", 2);
        // account 0xcafe, nonce 0, idx 0, APT, recipient 0xb0b, amount 400
        let m = digest(@0xcafe, 0, 0, apt, @0xb0b, 400);
        assert!(m == x"96662a83a81b07b57ff154f5bbe77d5921a8880f093781687565e1375ea861e5", 3);
        let root = x"1111111111111111111111111111111111111111111111111111111111111111";
        let rec_root = x"2222222222222222222222222222222222222222222222222222222222222222";
        let new_seed = x"55555555555555555555555555555555";
        let mr = recovery_digest(@0xcafe, 0, &root, &rec_root, &new_seed);
        assert!(mr == x"b51d7a3b8a09e001c289db3a3f6d6776084110a2c0153faacca35e1e572b1871", 4);
    }

    #[test(framework = @aptos_framework, creator = @0xa11ce)]
    fun test_create_fund_execute_cached_recover(framework: &signer, creator: &signer) acquires CchsAccount {
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);

        // Key material: bottom tree 0 with real leaves 0 and 1, top leaf 0, recovery leaf 0.
        let r0 = test_root(0, 0, 0, H, true);
        let top_root = test_root(1, 0, 0, H, false);
        let rec0 = test_root(LAYER_REC, 0, 0, REC_H, false);

        create(creator, top_root, rec0, TEST_SEED);
        let addr = derive_address(@0xa11ce, top_root);
        assert!(exists<CchsAccount>(addr), 0);
        assert!(creator_of(addr) == @0xa11ce, 1);
        assert!(needs_top_layer(addr), 2);

        // Fund the resource account; the creator key plays no further role.
        aptos_account::deposit_coins(addr, coin::mint<AptosCoin>(1000, &mint_cap));
        assert!(coin::balance<AptosCoin>(addr) == 1000, 3);

        // Op 0: first in subtree, needs the top layer. No signer involved.
        let m0 = next_digest<AptosCoin>(addr, @0xb0b, 400);
        assert!(m0 == digest_at<AptosCoin>(addr, 0, @0xb0b, 400), 15);
        execute_transfer<AptosCoin>(
            addr, @0xb0b, 400, 0,
            test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, true),
            true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false),
        );
        assert!(coin::balance<AptosCoin>(@0xb0b) == 400, 4);
        assert!(coin::balance<AptosCoin>(addr) == 600, 5);
        assert!(next_idx(addr) == 1 && nonce(addr) == 1, 6);
        assert!(!needs_top_layer(addr), 7);

        // Op 1: cached subtree, bottom layer only.
        let m1 = next_digest<AptosCoin>(addr, @0xb0b, 100);
        execute_transfer<AptosCoin>(
            addr, @0xb0b, 100, 1,
            test_sign(0, 0, 1, &m1), test_auth(0, 0, 1, H, true),
            false, vector::empty(), vector::empty(),
        );
        assert!(coin::balance<AptosCoin>(@0xb0b) == 500, 8);
        assert!(coin::balance<AptosCoin>(addr) == 500, 9);
        assert!(next_idx(addr) == 2, 10);

        // Recovery: rotate roots; address and funds stay.
        let new_root = x"3333333333333333333333333333333333333333333333333333333333333333";
        let new_rec = x"4444444444444444444444444444444444444444444444444444444444444444";
        let new_seed = x"55555555555555555555555555555555";
        let mr = next_recovery_digest(addr, new_root, new_rec, new_seed);
        recover(addr, new_root, new_rec, new_seed, test_sign(LAYER_REC, 0, 0, &mr), test_auth(LAYER_REC, 0, 0, REC_H, false));
        assert!(root(addr) == new_root && rec_root(addr) == new_rec && seed(addr) == new_seed, 11);
        assert!(epoch(addr) == 1 && next_idx(addr) == 0 && rec_nonce(addr) == 1, 12);
        assert!(needs_top_layer(addr), 13);
        assert!(coin::balance<AptosCoin>(addr) == 500, 14);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @aptos_framework, creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_replayed_signature_fails(framework: &signer, creator: &signer) acquires CchsAccount {
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);
        let r0 = test_root(0, 0, 0, H, false);
        let top_root = test_root(1, 0, 0, H, false);
        create(creator, top_root, test_root(LAYER_REC, 0, 0, REC_H, false), TEST_SEED);
        let addr = derive_address(@0xa11ce, top_root);
        aptos_account::deposit_coins(addr, coin::mint<AptosCoin>(1000, &mint_cap));

        let m0 = next_digest<AptosCoin>(addr, @0xb0b, 400);
        let l0 = test_sign(0, 0, 0, &m0);
        let a0 = test_auth(0, 0, 0, H, false);
        execute_transfer<AptosCoin>(addr, @0xb0b, 400, 0, l0, a0, true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false));
        // Same signature submitted at the next free leaf: the index and the
        // nonce are both in the digest, so the recomputed subtree root
        // differs from the cached one. (At its own leaf 0 it fails earlier,
        // with E_INDEX_USED; see test_index_reuse_fails.)
        execute_transfer<AptosCoin>(addr, @0xb0b, 400, 1, l0, a0, false, vector::empty(), vector::empty());
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @aptos_framework, creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_first_use_without_top_layer_fails(framework: &signer, creator: &signer) acquires CchsAccount {
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);
        let top_root = test_root(1, 0, 0, H, false);
        create(creator, top_root, test_root(LAYER_REC, 0, 0, REC_H, false), TEST_SEED);
        let addr = derive_address(@0xa11ce, top_root);
        aptos_account::deposit_coins(addr, coin::mint<AptosCoin>(1000, &mint_cap));
        let m0 = next_digest<AptosCoin>(addr, @0xb0b, 400);
        execute_transfer<AptosCoin>(addr, @0xb0b, 400, 0, test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, false), false, vector::empty(), vector::empty());
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @aptos_framework, creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x50007, location = Self)]
    fun test_wrong_amount_fails(framework: &signer, creator: &signer) acquires CchsAccount {
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);
        let r0 = test_root(0, 0, 0, H, false);
        let top_root = test_root(1, 0, 0, H, false);
        create(creator, top_root, test_root(LAYER_REC, 0, 0, REC_H, false), TEST_SEED);
        let addr = derive_address(@0xa11ce, top_root);
        aptos_account::deposit_coins(addr, coin::mint<AptosCoin>(1000, &mint_cap));
        // Signed for 400, submitted for 900: the bottom root no longer matches
        // the top-layer message, so the top layer fails against `root`.
        let m0 = next_digest<AptosCoin>(addr, @0xb0b, 400);
        execute_transfer<AptosCoin>(addr, @0xb0b, 900, 0, test_sign(0, 0, 0, &m0), test_auth(0, 0, 0, H, false), true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, false));
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    // ---- signer-chosen index. These tests exercise the index discipline,
    // the cache lookup by (epoch, tree) and the top-layer rule through
    // `test_apply`, which runs the state transition of `authorize` around an
    // already-known bottom root instead of paying for a bottom-layer WOTS+
    // verification per operation. The bottom root of subtree 1 is an
    // arbitrary value: only the top-layer signature over it is verified.

    #[test_only]
    const TEST_ROOT_L0_T1: vector<u8> = x"5151515151515151515151515151515151515151515151515151515151515151";

    // Account under a top tree whose leaves 0 and 1 are real, with subtree 0
    // (bottom root `test_root(0, 0, 0, H, false)`) registered through leaf 0
    // (`next_idx` = 1, `nonce` = 1). No funds are needed: `test_apply` moves none.
    #[test_only]
    fun test_account_with_subtree0(creator: &signer): address acquires CchsAccount {
        let r0 = test_root(0, 0, 0, H, false);
        let top_root = test_root(1, 0, 0, H, true);
        create(creator, top_root, test_root(LAYER_REC, 0, 0, REC_H, false), TEST_SEED);
        let addr = derive_address(signer::address_of(creator), top_root);
        assert!(needs_top_layer_at(addr, 0), 100);
        test_apply(addr, 0, r0, true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, true));
        assert!(next_idx(addr) == 1 && nonce(addr) == 1, 101);
        assert!(!needs_top_layer(addr), 102);
        addr
    }

    #[test_only]
    fun cached_root_of(acct_addr: address, tree_idx: u64): vector<u8> acquires CchsAccount {
        let acct = borrow_global<CchsAccount>(acct_addr);
        *table::borrow(&acct.cached_root, cache_key(acct.epoch, tree_idx))
    }

    #[test(creator = @0xa11ce)]
    fun test_skip_within_subtree_and_across_subtrees(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        let r0 = test_root(0, 0, 0, H, false);
        // Leaves 1..4 are skipped inside the registered subtree: cached path.
        assert!(!needs_top_layer_at(addr, 5), 0);
        test_apply(addr, 5, r0, false, vector::empty(), vector::empty());
        assert!(next_idx(addr) == 6 && nonce(addr) == 2, 1);
        // Jump to the first leaf of subtree 1: top leaf 1 must be presented.
        assert!(needs_top_layer_at(addr, 1024), 2);
        assert!(!needs_top_layer(addr), 3); // next_idx = 6 is still in subtree 0
        test_apply(addr, 1024, TEST_ROOT_L0_T1, true, test_sign(1, 0, 1, &TEST_ROOT_L0_T1), test_auth(1, 0, 1, H, true));
        assert!(next_idx(addr) == 1025 && nonce(addr) == 3, 4);
        assert!(!needs_top_layer_at(addr, 1024) && !needs_top_layer(addr), 5);
        assert!(cached_root_of(addr, 1) == TEST_ROOT_L0_T1, 6);
        assert!(cached_root_of(addr, 0) == r0, 7);
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_index_reuse_fails(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        let r0 = test_root(0, 0, 0, H, false);
        test_apply(addr, 5, r0, false, vector::empty(), vector::empty());
        // Abandoned leaves stay abandoned: 3 < next_idx = 6.
        test_apply(addr, 3, r0, false, vector::empty(), vector::empty());
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x1000a, location = Self)]
    fun test_same_index_twice_fails(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        // Leaf 0 was consumed by the registration; it is rejected before any hashing.
        test_apply(addr, 0, test_root(0, 0, 0, H, false), false, vector::empty(), vector::empty());
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x20004, location = Self)]
    fun test_index_beyond_capacity_fails(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        test_apply(addr, CAPACITY, test_root(0, 0, 0, H, false), false, vector::empty(), vector::empty());
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x10006, location = Self)]
    fun test_jump_to_fresh_subtree_without_top_layer_fails(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        test_apply(addr, 1024, TEST_ROOT_L0_T1, false, vector::empty(), vector::empty());
    }

    #[test(creator = @0xa11ce)]
    fun test_redundant_top_layer_is_ignored(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        let r0 = test_root(0, 0, 0, H, false);
        // A transaction prepared with the top layer before subtree 0 was
        // registered by someone else still succeeds: the proof is ignored.
        test_apply(addr, 1, r0, true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, true));
        assert!(next_idx(addr) == 2 && nonce(addr) == 2, 0);
        // Ignored means not inspected: only the cached root is compared.
        test_apply(addr, 2, r0, true, vector::empty(), vector::empty());
        assert!(next_idx(addr) == 3 && nonce(addr) == 3, 1);
        assert!(cached_root_of(addr, 0) == r0, 2);
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x50005, location = Self)]
    fun test_bottom_root_mismatch_in_registered_subtree_fails(creator: &signer) acquires CchsAccount {
        let addr = test_account_with_subtree0(creator);
        let r0 = test_root(0, 0, 0, H, false);
        // A bottom root that is not the registered one is rejected even with a
        // (redundant) top layer attached: the cache, not the proof, decides.
        test_apply(addr, 5, TEST_ROOT_L0_T1, true, test_sign(1, 0, 0, &r0), test_auth(1, 0, 0, H, true));
    }

    #[test(creator = @0xa11ce)]
    fun test_digest_at_binds_index(creator: &signer) acquires CchsAccount {
        let root = x"1111111111111111111111111111111111111111111111111111111111111111";
        create(creator, root, x"2222222222222222222222222222222222222222222222222222222222222222", TEST_SEED);
        let addr = derive_address(@0xa11ce, root);
        let d5 = digest_at<AptosCoin>(addr, 5, @0xb0b, 400);
        let d6 = digest_at<AptosCoin>(addr, 6, @0xb0b, 400);
        assert!(d5 != d6, 0);
        assert!(next_digest<AptosCoin>(addr, @0xb0b, 400) == digest_at<AptosCoin>(addr, 0, @0xb0b, 400), 1);
        assert!(next_digest_fa(addr, @0xa, @0xb0b, 400) == digest_at_fa(addr, 0, @0xa, @0xb0b, 400), 2);
        assert!(digest_at_fa(addr, 5, @0xa, @0xb0b, 400) != digest_at_fa(addr, 6, @0xa, @0xb0b, 400), 3);
        // Independent vectors: account 0xcafe, nonce 1, APT, recipient 0xb0b, amount 400.
        let apt = coin_asset_id<AptosCoin>();
        assert!(digest(@0xcafe, 1, 5, apt, @0xb0b, 400) == x"e0863adbfb431dc3ccde44d953cd8769cf13a315e24d780838816c13ec5d52d2", 4);
        assert!(digest(@0xcafe, 1, 6, apt, @0xb0b, 400) == x"536e59b13164add02f57c00d48a8e94e8ce45aa7465561afed67717538550950", 5);
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

    // Public seed of the fixture key tree (`seed` in cchs-s-20.json).
    #[test_only]
    const FIXTURE_SEED: vector<u8> = x"3807d89f250b16fa055f3ec3e1bd65a5";
    // Leaf 5 of bottom tree 0 (`skip.ops[0]`, idx 5).
    #[test_only]
    const FIXTURE_LEAF_L0_T0_5: vector<u8> = x"1830232019c75c9e2ab72f0249cae822246b80edc33b7087a65c9560b2c23214";
    // Leaf 0 of bottom tree 1 (`skip.ops[1]`, idx 1024).
    #[test_only]
    const FIXTURE_LEAF_L0_T1_0: vector<u8> = x"1c111532ccc50d0476cd19800d358e8a5066911652c4067dd308ec020d93694a";
    // Top-layer leaf 0 (signs `bottomRoot0`; sibling of top leaf 1, so it is `skip.ops[1].l1.auth[0]`).
    #[test_only]
    const FIXTURE_LEAF_L1_T0_0: vector<u8> = x"3774c3b9f1f6441f0ba83061f84147ab042fe9810fef3b546e6389af5d342d5b";
    // Top-layer leaf 1 (signs `bottomRoot1`; sibling of top leaf 0, so it is `ops[0].l1.auth[0]`).
    #[test_only]
    const FIXTURE_LEAF_L1_T0_1: vector<u8> = x"9cc3a4f7b8692784cfb68ecfa1c5f1b839bf6d13b4d21bb12918df7bbd8c280c";
    #[test_only]
    const FIXTURE_ROOT: vector<u8> = x"08f0d64029c76bbc5c5dac1f51d6ef8920b3daff5165d4051d7580da3c79762d";
    #[test_only]
    const FIXTURE_BOTTOM_ROOT0: vector<u8> = x"f6da7162aa497dbfa63dd60bf7a23a5da7591429a7489410d2affe322a1f3af4";
    #[test_only]
    const FIXTURE_BOTTOM_ROOT1: vector<u8> = x"862abc2cf7edf525b36c923eb1447b52a076c6cd42e5e6ae11ea8d978352a759";

    #[test]
    fun test_fixture_skip_leaf5_path_matches_bottom_root0() {
        assert!(merkle_root(&FIXTURE_SEED, 0, 0, 5, H, FIXTURE_LEAF_L0_T0_5, &fixture_skip_a_l0_auth()) == FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_fixture_skip_leaf5_at_shifted_index_mismatches() {
        // Leaf 5's material presented as leaf 6: the position flips the node
        // order and changes every node ADRS, so the subtree root differs and
        // an `execute_transfer` at idx 6 with this signature aborts with
        // E_BAD_SUBTREE_ROOT. (The WOTS+ digits would differ as well, since
        // the index is in the digest.)
        assert!(merkle_root(&FIXTURE_SEED, 0, 0, 6, H, FIXTURE_LEAF_L0_T0_5, &fixture_skip_a_l0_auth()) != FIXTURE_BOTTOM_ROOT0, 0);
    }

    #[test]
    fun test_fixture_skip_leaf1024_path_matches_bottom_root1() {
        assert!(merkle_root(&FIXTURE_SEED, 0, 1, 0, H, FIXTURE_LEAF_L0_T1_0, &fixture_skip_b_l0_auth()) == FIXTURE_BOTTOM_ROOT1, 0);
    }

    #[test]
    fun test_fixture_skip_leaf1024_full_layer0_matches_bottom_root1() {
        // skip.ops[1]: idx 1024 -> tree 1, leaf 0; the signed message is skip.ops[1].digest.
        let m = x"b66cd1ee383ae8930b7afea625bb3e949cef3ca216c52d800f78c85c8a659c33";
        let r0 = verify_layer(&FIXTURE_SEED, 0, 1, 0, H, &m, &fixture_skip_b_l0_wots(), &fixture_skip_b_l0_auth());
        assert!(r0 == FIXTURE_BOTTOM_ROOT1, 0);
    }

    #[test]
    fun test_fixture_skip_top_leaf1_path_matches_root() {
        // skip.ops[1].l1: top layer, leaf = tree_idx = 1, message = bottomRoot1.
        assert!(merkle_root(&FIXTURE_SEED, 1, 0, 1, H, FIXTURE_LEAF_L1_T0_1, &fixture_skip_b_l1_auth()) == FIXTURE_ROOT, 0);
        // Top leaves 0 and 1 are siblings: each appears at level 0 of the other's path.
        assert!(*vector::borrow(&fixture_op0_l1_auth(), 0) == FIXTURE_LEAF_L1_T0_1, 1);
        assert!(merkle_root(&FIXTURE_SEED, 1, 0, 0, H, FIXTURE_LEAF_L1_T0_0, &fixture_op0_l1_auth()) == FIXTURE_ROOT, 2);
    }

    #[test(creator = @0xa11ce)]
    #[expected_failure(abort_code = 0x8000f, location = aptos_framework::account)]
    fun test_create_twice_same_root_fails(creator: &signer) {
        let root = x"1111111111111111111111111111111111111111111111111111111111111111";
        let rec = x"2222222222222222222222222222222222222222222222222222222222222222";
        create(creator, root, rec, TEST_SEED);
        create(creator, root, rec, TEST_SEED);
    }

    // ---- test-only key material. A WOTS+ key whose chain secrets are
    // sha2_256 of a tag; sibling nodes are either the real neighbour leaf
    // (level 0, `real_sibling`) or tagged pseudo-random values. Verification
    // only recomputes the root from leaf and path, so this is a valid tree.

    /// Public seed of the test-only key trees (all zero, so the test trees
    /// are independent of the fixture seed).
    #[test_only]
    const TEST_SEED: vector<u8> = x"00000000000000000000000000000000";

    #[test_only]
    fun test_sk(layer: u8, tree_idx: u64, leaf_idx: u64, c: u64): vector<u8> {
        let buf = b"AEGIS_TEST_SK";
        vector::push_back(&mut buf, layer);
        vector::append(&mut buf, be64(tree_idx));
        vector::append(&mut buf, be64(leaf_idx));
        vector::append(&mut buf, be64(c));
        hash::sha2_256(buf)
    }

    #[test_only]
    fun test_chain(layer: u8, tree_idx: u64, leaf_idx: u64, c: u64, x: vector<u8>, from: u8, to: u8): vector<u8> {
        let s = from;
        while (s < to) {
            let input = adrs(&TEST_SEED, layer, tree_idx, 0x00, leaf_idx, (c as u8), s);
            vector::append(&mut input, x);
            x = hash::sha2_256(input);
            s = s + 1;
        };
        x
    }

    #[test_only]
    fun test_leaf(layer: u8, tree_idx: u64, leaf_idx: u64): vector<u8> {
        let buf = adrs(&TEST_SEED, layer, tree_idx, 0x01, leaf_idx, 0, 0);
        let c = 0;
        while (c < LEN) {
            vector::append(&mut buf, test_chain(layer, tree_idx, leaf_idx, c, test_sk(layer, tree_idx, leaf_idx, c), 0, 15));
            c = c + 1;
        };
        hash::sha2_256(buf)
    }

    #[test_only]
    fun test_sign(layer: u8, tree_idx: u64, leaf_idx: u64, m: &vector<u8>): vector<vector<u8>> {
        let d = digits(m);
        let sig = vector::empty<vector<u8>>();
        let c = 0;
        while (c < LEN) {
            let dc = *vector::borrow(&d, c);
            vector::push_back(&mut sig, test_chain(layer, tree_idx, leaf_idx, c, test_sk(layer, tree_idx, leaf_idx, c), 0, dc));
            c = c + 1;
        };
        sig
    }

    #[test_only]
    fun test_auth(layer: u8, tree_idx: u64, leaf_idx: u64, height: u64, real_sibling: bool): vector<vector<u8>> {
        let auth = vector::empty<vector<u8>>();
        let k = 0;
        while (k < height) {
            let node_idx = (leaf_idx >> (k as u8)) ^ 1;
            let sib = if (k == 0 && real_sibling) {
                test_leaf(layer, tree_idx, node_idx)
            } else {
                let buf = b"AEGIS_TEST_NODE";
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
        merkle_root(&TEST_SEED, layer, tree_idx, leaf_idx, height, test_leaf(layer, tree_idx, leaf_idx), &test_auth(layer, tree_idx, leaf_idx, height, real_sibling))
    }

    // State transition of `authorize` for an operation at `idx` whose
    // bottom-layer root is already known to be `r0`: index discipline,
    // subtree settlement (cache lookup or top-layer registration) and
    // counter update, in that order. Skips the bottom-layer WOTS+
    // verification and moves no asset.
    #[test_only]
    fun test_apply(
        acct_addr: address,
        idx: u64,
        r0: vector<u8>,
        has_l1: bool,
        l1_wots: vector<vector<u8>>,
        l1_auth: vector<vector<u8>>,
    ) acquires CchsAccount {
        let acct = borrow_global_mut<CchsAccount>(acct_addr);
        check_index(acct, idx);
        settle_subtree(acct, acct_addr, idx, r0, has_l1, &l1_wots, &l1_auth);
        advance(acct, idx);
    }

    #[test_only]
    fun fixture_op1_l0_wots(): vector<vector<u8>> {
        vector[
            x"8ea6272780ad240f7dc82b6dd090bb4ac21b2d71c18c52a41179029d4ad27873",
            x"9765927cff2dda0bc01cdd6be5cc0c3651330763a16ce0eeb18cfe53e25af7da",
            x"5b7f98ecff37e2cd29b9adec3bcf1dc128bb005359828975d079eb4505c0ee9e",
            x"5077019b92cdb1b7aeb9294185e751d8cbc402c50149b11f639841485baf4533",
            x"00038b72b53417ef016094de4f850ec3bfcdafbe7fdb01607515c648199cf94d",
            x"012ff2b8d0f7740a909800e14873109dd28ac8c44c0af7a513ad3ab1d91679a8",
            x"4b291c6875b6d549a647d575a0ee54d771b3499d7643dcab6b0957f08b6658e7",
            x"d9e9b936957542ddd2fa159dcc401ecb908f52610d1c912e2b057569af882230",
            x"c685233b1ac5118afe8254b74b86152adb870f36800cea83dcf46aa562baf3f9",
            x"dee55c760370081ea61c9b00b92694febb1132ecaa37677d4caa5e8aa16c04eb",
            x"bd3cd136b15851ef82bed5df68f5943fc9512ac7974f990a6cf2699ecaced7dc",
            x"3cc3d66c38ca0042b13cee81b4987821457d16d6dc9f6dbfa8fa8b611bff963f",
            x"2628c71b883df72bf1847b92ff2e078868ac738c058fc0a24f42b6d6e4096403",
            x"72ca917192ef82a96caa33f0bdf929b7cf5de47f05ba6ee8b1498cec0662d8ed",
            x"d3412b0e09f889aac63a189cf267ae78dd7b466aaf05fec07d05b85b0d31e0c2",
            x"d36962d586a81707a0a881b6dbd3d392b91e6b0a31270a1cf3c95981444d356f",
            x"6ead864ca29ccbf1cb9997998f195d61068121efcfa3facbc606478fd9d11176",
            x"a47f91d99cf2266c13c284cccdc831c5a73dbe549db38fdc2a1e89e0f06b3c8e",
            x"b553db92b6f3aaeb903a6934a1adc13be1c17d637e9f97397fefd1bfa3f2ae50",
            x"b42de23aa1b441a80a408ef7da2025b67bc822976431fa363c1176886cff3d58",
            x"a366405adf7935556f637d2a3b285584abb2f500c8b723b68330eb9e5c189d80",
            x"5310ef9dc8e74a2a7364575e1919471734c784efb12cb814a2fbaa325da67c3b",
            x"2276097e8e89c615ced336109d565af438868b8978ed77301a4e27670607966e",
            x"db38b827dc0345fccde7885f571a030f95b37abe51419bbbbce8a1505da24543",
            x"5832fc1a81afe68cb136bfe7267de1be92dd89f0a50c9afac8a7446e7c3935e1",
            x"21fc93f555d935e63c780cb88e6205acac3387d17cb1514ac2ca36975cb4de92",
            x"c4589aebbd0e1a03aabcc56998021d6e711446c5ba6ae10b1b9b8e3867144dfc",
            x"20ff8efaa9c232bc9e91d96f56ff262920b610473f11533ec9936ead7e0ade7d",
            x"7d0d6c17a8ffc8d079583bbe4dcb66d1e6d52d84da1661b1ea2160284d6eed05",
            x"e2e61358e45fdf62914645145c8a574464700a060ea4cfd053f2e719e1801eca",
            x"ee4f199b95b04379805acdf823b0c4fe23bc9a43ac61702732166d528dc19d20",
            x"4550a498c6914980016eac297db7ffdea31984fd9cda042e4b6dbbe6019f0f85",
            x"592bb3f7b94c4cc2d28d289059818475a0ab07ee879440da389602a223de605c",
            x"097e201667ca6802e60a9b978f9ccd384545247b46b09b4470c4a706d57bdbaf",
            x"1e18abeca53437b69b9bc37326d8e9f036357fed772feb356756d5aa016b086e",
            x"2c07b3cd887742225e149b671687224d4bcfe50f4a77f7f107eba0da909510db",
            x"5894cb79bbeb6129457e804958ffddbf471e3d24b20032f69de0618773ff4c74",
            x"31910fd637876ff9acf84eed87e3149cdae584b27e89a2edd49887276f5f44a0",
            x"47ac186f5108bbffcf651f44a75f4dbbbad2e31e6af118f67efec8a0118bff2c",
            x"63c6093d42337ec7cabd727cdf35cbe4af578c15c2ee7098f82d323d9e19c3ad",
            x"0558a7e4e6bde8d672a3110a3249adae904d05d6ebb8d74fb857e23ca65e3430",
            x"f6822bf7ffc8c5c06fc65ddebbad2c18ac055ce1636f76e37c845d0e7611b611",
            x"b187efb8b0e2b6e733a761c29f75c2bcb3673776f0e1c6c0c99e742baa729c08",
            x"e41acda343992707890b6e212aaba9bb73cbbd5711587e88090490885eec28dd",
            x"39c0677bca5edb09a2fde2e480879199448f3289234c84c461cff77523a471b6",
            x"f989574e8f9a72d62a1e744fcc16946fd846849cd39b958cedb5ec2fdaf60567",
            x"8fabf9f35684e94790343218287451aa101535735b571aac0cc8165382445f5e",
            x"38f04d147b053ac82b5f771f025ef2d1d6f381c49df997926ac72cb3a0dd66d1",
            x"a1beeff76f74852ca592b5f5ef6f97786b09271f44cf17dc26c827cf29fbea2d",
            x"0e3e9f515918a39060234b9904f62cb22e8cd76212634776d88875cfb27fdf0f",
            x"935fc0d32a91843971a44b1389b8c2b95290bc646ca06b75678297360682481c",
            x"5050908586804d3b51fe825b9ca4535ecdcd5b925f13479545890dbd1f65f218",
            x"42fad7b795dce960ca189b37a8c59c5e88261b8ff1f4af1b05211fe2786baf1b",
            x"2f186825bae762094aa4ad822af781b434b58c34668e4d4d6862d69d5cfb390d",
            x"5f4dcf51bf65b3fd380a3644ef58c00e28844e688de9298c39a77a6ac3e02813",
            x"33e47d74409e3b64644be592713308a4d84e0eb62c2ad47d521bfcf18274967d",
            x"a97b60f772099df7e5a2a9190fa3c9b89a9d6f2634d6071670078215e0b71f87",
            x"0cf2cb7ac3de78f03f8d897c6c9f3d45e8f45b1e42ad25e8b29e015ed58f9c8f",
            x"780329c9fe52ef5b34a94e3288a39e3eef6d65080aca3a1d2500c93c81346454",
            x"3b4220d930d531f56fbf6c4dd4fbdf010226e0e6acd89bdafe2500697b85d7d7",
            x"aa94b058b6c004477d0ed3c8aa400d8e7b9b99cbb59735e583bddbef891306cf",
            x"c7552432ef193931479c0543d440d63597cd6518d093253c7974f9a5bf984619",
            x"73f2f88af1edbe3afa599aa51bc8ed1481915c6e1252fee770b4ed02a38e13a8",
            x"ff1568f0a5ecb09a5e1fecc99ceb5cee88dca47567498c61ce095416066904a1",
            x"4bb77d1956acc4003372d81fffd6d27f96ec45eabeb72fe23fe23e8f88d062c7",
            x"0e173bfb1fa245b82457250db24d770ff8df25bde7497d0050198267d64f95b3",
            x"cfa42e81ce030cb5bccdc3260ef42385babecbbdf08df827dbe8e160d2de1646",
        ]
    }

    #[test_only]
    fun fixture_op1_l0_auth(): vector<vector<u8>> {
        vector[
            x"c370033356a66e9f1fa83c88a9994a6cd2d26effb8d808eff2369a42234a0343",
            x"d933d4d829c4c2e447887a177989e94c9667c1a2c5517c389186daa2502ae35a",
            x"cb0fdba37c4ea8bbf234c2b5cd0375a004984c9d645f08d2acedbd3f7454bda5",
            x"1c1742681dd27a9b4db2c3132a6644642fe1b314dd52c42f7a1319efb8fc1251",
            x"fc38c45df857bc7f6e87a1313c3483ccfee0cf7dece1de51b14cd8e100cfb423",
            x"141ec34645751ef15f99000b543d1ba29316dc0db1df067730978edee4ce2f76",
            x"24a23886f8cf8d1b5f2bb23565bfde289be5f8476f33fe8413a3f8b757490cc9",
            x"640857986fb250218d967098c1b55985bb35dfb6ddab797df99998b03d15b726",
            x"36d6264b659d94a7641998a483348fb0cfd6ef5d6701a5ae3902e8b7823b92ed",
            x"529438c49e2b338b60d23d9c352fa165801becfdd1a07441720d01d843df3ec5",
        ]
    }

    #[test_only]
    fun fixture_op0_l1_wots(): vector<vector<u8>> {
        vector[
            x"a129b67359995947545903464bad5922e1bd566308b288556f9f00a7203ed5f7",
            x"130d0462688e8b01d3c4afcd95526c8fa62a72755aa961d4dd00cecd7f8f1cf8",
            x"b2a38b1eee674e9696274f1d20b4a407a4aac81dbb6095c140b3dfa95123f414",
            x"1b402a3a721ebfdbf9e23e6b2c880bf4a1a146cb253944cd394639e60f12687d",
            x"16b43656772d61614b794929e20820ca0ec3fed22933d44d9b788ff46f4406cb",
            x"e470370b0be8dadd95d60d4b1fc02c6e9a47cee5a61c9fc0f663db8c02a2d9cd",
            x"eeec8297377ebfb09352f1f00c2a9ba69e331dd6ba352a9a30d976c4eab57774",
            x"876eae96bacfdbfabba798d41b528930f18a3e8273224ab4be4dbabcae232801",
            x"d77def98feffcb1892c7dd6ca64cf748af1b04426d80d5bf377c44a2178e0311",
            x"76480b4ccc3a4c7ded8c4edcfe4810e045ef4f130bd7ddf98797868a36fcfb85",
            x"ff69374a1fbfbff49ccbc618bb96eeacfe8085b54a30af567fbc8c1bd31827f8",
            x"f8cf94511eb66842888e9f3c2d8b0b8cebeca1adbd5995c2625710d03c808b7a",
            x"cd1f00566fd0f2000309ca863729af79008effe5ec40d5a123a2a0ea74af57df",
            x"06e7133b63ec7e8929587d8fc6c6ff0832b0c64a4d726b8cf86bca2ce71a57ca",
            x"d8472632aeb9b196aa680075d658dd7f9a7f9e20a7ca5ecd21262e62e01358e2",
            x"558f4fcb14e2edf753ba4c0d0f9a62426c1df441eccb934fb54466d370b44d41",
            x"a940cf9df568613ab2466bbce8193a9d88a9db589b5b131397e48e1623fef3b1",
            x"94acba0c581b8983b6f1c801c16df614b10b318259930a8c7b2c4b1b1b928a3d",
            x"f139f6388e684acb8fba330d13252f937a0c1a48aa1ccd31ff00cdb463d446a2",
            x"4405da81745e37b77b911d2f77d93797ba06fe6658a7a2ac002f210b7546e822",
            x"abdce273636f713859448354bd7f6e34028a83259017cecff4d6ccda7559c322",
            x"599476b15654452c38e3d39bc372f79714e431006e130adb729859ac915d3671",
            x"aaadc03e9075e6a0b72dbdd82cee2674f5467f7299e134effc945590027cacfc",
            x"6ac0e31fb248b39f7cac92c2829dca6963ed045a866edd2b7d55c988568bbfbe",
            x"69ee391976a874dafe7f19b2127c528f6bf2b598501e2694af6b3da6ba65f3ac",
            x"6c3b7924dd7b9cd7edb4dee27516a5260b8872ef96bcb128ea1a2a559eb745e7",
            x"0a620e8e3fa3df5eb7c311b87d3d2a410f8cc78e73f8c6436a2ceee971857b1b",
            x"45c3105f7ba61841ca86b387c1bdca1ef27793d0b90d5b1734bea33e3ee490b7",
            x"b84414f43d12a65596f332ea01f3639039d97852598995e5f21e24b880aa4b41",
            x"a3c08ce9888cc26052c4f9b2817b1c290cec9d03b07be6b1aa083ca6c7103231",
            x"1d7d6bfc0a85038b65ce831026c1f69bcdca04310e32ca0055c4d738413e5458",
            x"3422b123c844f4eb796acb8eb8bbb89e40d6f19ca9c5307b2925927ef4af6ef8",
            x"412c5767af3910000c8a6c70be9bce8b3ceec046490491e32b1cfc7997d107b1",
            x"a745e7329af68d34dbfdf1182e5d296eef57a33fdc4da40c93896a56f6b1eb28",
            x"00f1bb4a72b5efa7a9730931185ff19596d23a408e457a3bd6a97ae8eed6992c",
            x"7d49caf572f306a5f10143300890e84f550785ad4b3dd63672ac126c1b57d93e",
            x"c6259eda0dbaf11d7f52eeaf4fae54cb1f20f54055cf59b604ac55bd32b59b0a",
            x"01ea4f9b6ab1cdb65dcea0bdf5eef856bd1a42681c3e9bf69109b7a908ae6f79",
            x"4bbc8958c6c1a8c92474b1e4f3fdb077cdf37af7cccf80b7fab9b59d745df0b0",
            x"790b6e8e27d8a993c059ff62d66117ec6b9200b27bb14aa22c4131a2e3e07c4b",
            x"31767166002b3630f3a96a68d2a8a2777330984c55aad7f5998ef63ae5a55906",
            x"99aa4b5761d72ab2e578939865f36494724acce3170cc0628406422727faf5ce",
            x"4b77310ddf9998e4b713c2bc8ad60ca098eb189c7689d6de2b4810350aa68a83",
            x"2fcefa78ef38a17dfa9b534ac543ee7b47e93769de75ce87a81a305d2ac25841",
            x"becd1375873d7dd7b8144d143cbcc970b8ef68ed1b522fa46739f38c32b3d82b",
            x"d8d09da5e074912a0ca146f4eade066e2fe1d5482be9eab530376d1d3e9840a9",
            x"15033465ac1927ae532868d0e474e8cb699778fb497a61ad63232696ecd80d15",
            x"c995fca4475eb89dd3e3e1dc05103af50a9140e6297f90180b2ec80d9514d91f",
            x"e5616e9f6c4f4d408e86ac0920ecce063b1184a90c20ef5526549dea9d3a6a53",
            x"89e277cd5ea9077b19f583a9a249b3969e50b6771c82d5a2423b9cf2f57331ff",
            x"8460a36f315b39f68718a3dcc8475cc8db69d5de28fcbd81897c5c4ae88e79f6",
            x"2f8358f6530153c1712462bb6512d620bd65459a0441ee094058b5a82e096f44",
            x"978f1de488bfe1c89a8567058f733c2ac9b1350ffc5d99cdfe868cc04af50c8e",
            x"fd668b11af796b6ff3eee0db310c7afd01827f727ae0226dc4cad497bd4c145e",
            x"fb44160db944b097cb7af1cb7853a0e21af9c7e6cedd46d7ae73a11d100be6cf",
            x"f80e9fedd84e1f418bd55e0e7c5607010e010bf8a064c771b53843c698b9a9be",
            x"4e824b658fffba9807d4fdfb62521de5adbe0b60dcf1ad718f19171823e7aa09",
            x"e932e07efd5ea0b7d4559571279da2aa0a234fda553aefced7e5370d68f81a7b",
            x"b51094d9377473c332193709804d849f06b59ffc5d6133478de431600dea6dcf",
            x"8d271c01e242d6403ca6eafa5df24f3cb115a92a2cb2a875c085f12c6e1b51fe",
            x"b00b8bd23cc080a1a485b84abebbb42166ab9f9b40fff42556a8ebbd6ae81a5e",
            x"68d19a5fdfa28de5ad617f278490e172e1cddb9382ebbf10abf3d9d29a012638",
            x"dc7b0960a085307063b6fad6d8921f3cdf4e3162acaeac4021b4849cde04282d",
            x"8d4e179e74822a4d227df0af9bd04572b26ade644898c16b2b73be28dcd4e2db",
            x"6d344671d81087387bfbefbf6ee4af7fb992945d9fb5d06876a713ecbd9b4ee2",
            x"38047aac7bcf5ba334f9c3e8828806beb59f335f779474cfb33edceaae5b7fe1",
            x"2d6ca4cf742c8c5b8a106208a0e9dde501baa687348c7aa5133796e0cc92f3e0",
        ]
    }

    #[test_only]
    fun fixture_op0_l1_auth(): vector<vector<u8>> {
        vector[
            x"9cc3a4f7b8692784cfb68ecfa1c5f1b839bf6d13b4d21bb12918df7bbd8c280c",
            x"903dacfaf46f6ae52895f1519f792212ec81ce044df3d0af6b5dfd1ab6a42ca5",
            x"8c9414719d9ed2641e19677673af342c33537be8a419340d03e8f3b2ea141bdf",
            x"9e9fa74db087131c8023a1d8f7b45477a3486d59d9e66db93f3df7756bd638f3",
            x"cbf49ceaf4e05afe62a052d6656d491b83031b67ea1862085b45f8d8cbc4857e",
            x"ddbd0cd48282cedb2a56f5b0add28df5fdc41ca65d4a76dc3a40614b8d8841b6",
            x"b6f08980dc9e1aa69152892402380fd8bb937a488eb1ce16a000e9606077c7d6",
            x"3a76d898fddc7225e9a088b45b8dcc5401022ff413d679d7224f10ad86239c67",
            x"812f263c01d99cd83de82df7ca999050e4e71ca900e2ee766f98c4746c02c11a",
            x"f1ebba2e533ec4e5884aef803d86ec20cc573ae77bcfd91dd77db0ac35a88af6",
        ]
    }

    // skip.ops[0].l0.auth: leaf 5 of bottom tree 0.
    #[test_only]
    fun fixture_skip_a_l0_auth(): vector<vector<u8>> {
        vector[
            x"9b4c481e8c6591ff73861f50c68aa8ebffbd98ba7a7309d1c54b328ac749c87d",
            x"ff1d6063caa1e6e241f6e2903bb4bb3cbbf7b6938fed4f9ee98c3c58b617a862",
            x"52c229bb623bb59ba6c728fa978107eee711fd0cbd8c60f0eb7449c50af15177",
            x"1c1742681dd27a9b4db2c3132a6644642fe1b314dd52c42f7a1319efb8fc1251",
            x"fc38c45df857bc7f6e87a1313c3483ccfee0cf7dece1de51b14cd8e100cfb423",
            x"141ec34645751ef15f99000b543d1ba29316dc0db1df067730978edee4ce2f76",
            x"24a23886f8cf8d1b5f2bb23565bfde289be5f8476f33fe8413a3f8b757490cc9",
            x"640857986fb250218d967098c1b55985bb35dfb6ddab797df99998b03d15b726",
            x"36d6264b659d94a7641998a483348fb0cfd6ef5d6701a5ae3902e8b7823b92ed",
            x"529438c49e2b338b60d23d9c352fa165801becfdd1a07441720d01d843df3ec5",
        ]
    }

    // skip.ops[1].l0.wots: WOTS+ signature at leaf 0 of bottom tree 1.
    #[test_only]
    fun fixture_skip_b_l0_wots(): vector<vector<u8>> {
        vector[
            x"bcc1bd3e1dc5dddaa5442829867476d03ecca8ceb4ae3703584d703467f8415c",
            x"631d7dbd0519d9bdd8581d47a09318648cb1648ad1f15891ba52b3b924c3bbac",
            x"175340363c2745f093dd688e16b9892656f40926ef625ee03aaf2ded2a571c7b",
            x"145bb4829c9bf2690390fd41eaddfe42007c832e9e33256060a091254dd39261",
            x"ed80c8e1eeb881c7d444b22c73c278683bf20d5bccf60765a796c8ab0b2f05eb",
            x"f99172f3ef2b9ba53a764894af49da99703528af69460f4675b88dd9204915c7",
            x"7ed3cd219906b28cec408c34cd496f8adf63826ff7bac299229159d7f07429c2",
            x"db74fdf860178c8a0b6c72af3434c7ccd0fcccd08765fcbe29ede3a481da90fe",
            x"26fd8d49627250e3e63b64d9937c5be9cae7ef3dc80b2eff301b30084e877616",
            x"ca1eaed91e64d9211617479d8483cf19b3a46e7de7bba454d847246cdef3e307",
            x"426be47b35b211af46e5a45586f12ad9317bd572d893fbe51bd41ee39b0ece4c",
            x"c6275782abe8052ccdc1692c340ba4aea5046dc8c59de83c1e27a935953b9bdb",
            x"8e91f9c6d769248f59644cac1e33a2e9d3e019f5c4406bc062390f339aeddc53",
            x"cbda841d86c009f7f951ec8b38d456737b879a2a3fa14194112de3a02abb10b6",
            x"0e3f51780e48fa4d202184cffa1c512ffaf48561d46aa9e5071f85f384e79fc1",
            x"b72bfe49b4bf331b3affb8e362d41203b9623e897cc4e8d8c485571fbf2170d2",
            x"3f452a3a085ddc2973c3cf0c13d841af3c7ae3f830898976674c0a2c2d156277",
            x"0acd4f2ff79db516a58fc2899574b98d4a32c906844799ff8f84c13137e58b39",
            x"d40d4ca144aa9be13d6f2dad94c5fd53183d8544bd7164d300c6dc582e2bfb5b",
            x"afa631115505a9afafc1b4a853de90f3690a8dcf773865fd9c9f8513ac6eedae",
            x"e5846a79b3b5f6fc443690955a37663e9c75f3a0b73a750280c82dfcdc4f7f6d",
            x"40e48d07a5b5283ceed185fa6e2699d5b183dae7f58dad72fa016ffe307a2448",
            x"e9493c3987e5a9e638a7827340bb3ace1f13409d94b3c9f8a009c52f273b615e",
            x"362165c7ca9dee68913933bec3e9d5704ad25f0b077bb6b14c90e39aeebf26aa",
            x"fc23476274b02d99a8cbe8e72c208c119108d7dc20a3cdc5de404fdf2da0e14d",
            x"98facd0ec532c11e3c4c12d43be0878fe064787eede11ee3624d4bc4296c7289",
            x"ee61dd38eba7f1a05922cc094b3e7f92834788af710532bfb745fde489df1fd2",
            x"61c59de4b9166484217572b9be1152e03ed8924961961d213c766d37ae271635",
            x"5965bb958e8e589b1231fbd912717a74b1c3ab5f2397b99f2066971caf602c84",
            x"fa10c73e61c152bd3775647eedfa3638c6034745308a83397fe2ed2a9cf54910",
            x"775bffa2841d3cbff0a4cea5fdef821227ea3ff2306f9ff611c1a5e2fa549297",
            x"e3220d00b9fe31aeed1a51042e4622f709c5bba0ad6797bb15be66165d8ff2c9",
            x"52a9b91564816a4a64aa01266db0ccf4b6bca0c36c181bd29d672acc1cfd4e63",
            x"56bac3ee7b90752478a7ba5aa1f678b8b1d6315c364eeae4c3f76ea7aaa3b803",
            x"6127264a9b48e2304e860cb68d018cb8ef2a56e086ba6d13b15e7a6c29006c21",
            x"17ac3f4e1db9cf68d4ba92dd8451081e189daa772ea4a22ac2be08f20889cfe0",
            x"647fa0f9be7d2e03e188e6d04c302cdcf79782cc364321a725cf76253859b398",
            x"9366ce7d5606677f2a19d6f31e0657c34ed98dcba25f3a4a8db5257c322b41a3",
            x"1d64707a0d6f7cffdb1127edd0cfa4721b4405286fad53fd28f8bbb5fd625d28",
            x"de934977c3acc90f6766a1ee5802bee72bbce36a636c32d901d1dbb483e4e56e",
            x"2fcb6240fcaff583dce73399a138f12ecd96321fccbefa36729033b8347b7bd2",
            x"763d7917c869c43dcce70f84b9b748067a3f30e23fc9fd1c0810f8eed6fbcbf2",
            x"9fd199a23d526f35a2206478f01fc9d1f519c083e82b362020bb8802e581d990",
            x"84eabfa96fa5909f95275caf2c1583aa231bc6b55d08b6b829d7fb36f7e3fc3c",
            x"5a01687016b6cfa62269a6a8da8b951402307ec6397a075f4b8ee35bb59fe8f6",
            x"5c95685fded8b3e9c3a08a93483a8c792b1ad09afc05d45029f2032a8df4e01f",
            x"f601529b2dfdfe7864713bc4b5b1755203da5885716cf4f1effaf295984b1ada",
            x"cf082bb9b1a1a24a1aef13b46e0a45c571088f56c1df4b603444137f1ea4ff6d",
            x"844830cfeca567fd6c504b2698723d85476e572c9d7ea4931946a92981d9e087",
            x"4a1200c34be2f36fce31af4ccae5b50e62b627229e309eec5dbb075fab2f79da",
            x"e5a133618e40dde246e120371313ad53493670399fcff02e8c448500521093e5",
            x"2a674b054755bbfdf0a42577407c86313f8f76baf5ffd16149fae8e17e2e546b",
            x"06ff3c498a21a13aa51f8339622c33f1252220cf6481af49bf64918cdf713b2f",
            x"5f37600f034d26e4b03e6d89100326ff88ae77d0b8e6c3cbf667865d76c31cef",
            x"1c470c3ee485fb66d874f103fd7008e8752a3900a9c817b091cea70e3cf68f82",
            x"5b3c43a7f19363de05b912d451046fdddddab9135394e04e81cb00cb0a50faa7",
            x"2e2ca8df09a47a94fa8f5d3dddc8470fdba3c8358a0d7b08cfda851c8e681f81",
            x"c4a1ec141e41cc7f387cc61ddea0010f2a7ff7e43cb0f1a45efaf1b5aab6525a",
            x"5ad652e888f480e9d8233efe2c9caeca80d0c2c93752431fe90faef7dfb84473",
            x"5abe10cca6228ffd4f1e142dc103d359062979294bf371528bad1d083cc3315b",
            x"4b3b5774674605f8e71fc1e44bbdefda32804d80b3c479caf9f93c54f279f2df",
            x"9569277815dbbe6cf3fb2c95c027e082ee9b59422162f8c8c8cc793e55a50a26",
            x"36fb08c2d263c504d674c58324c83cb2504b4e6220e74328a3de8b823637e08a",
            x"fa172961ba4af43fb49e1e9f4e161dc3e70da8906153a5146f6437a97ef7ee1b",
            x"3eb8ab08129a9a9a3b1f34cd6141769634944ffd72667614eb0773eb755a6ee2",
            x"14712084fbd14eebd00bf5215698cd740c7aa91a55e7bb3684ce2e9766bc019b",
            x"b1604728eda92b19ec7be95e4ce25c93643c676f3b39db069d9b44ea3d3489cb",
        ]
    }

    // skip.ops[1].l0.auth: leaf 0 of bottom tree 1.
    #[test_only]
    fun fixture_skip_b_l0_auth(): vector<vector<u8>> {
        vector[
            x"4b584ea11bc0473aaf22f57762bef979d5c10f9a0e660cd821af1de23966f148",
            x"2145ad96ebfd94c9ca8f0d971b82f23ff7fe73e00fae40e8b0dc68faddb4d008",
            x"bb8749f49bd4f986901064c9fc6e7653e0239f81939a99ab338869522e68e58f",
            x"532b405b0adc5474fa65a4ba794747281fccf3579d8a87da445ad347ebe18b4c",
            x"63c6d0ba8cd77ad2184a644605f1df71025f0a0b9e6442174a23d0c4cc874891",
            x"0b65abe1282142954ce8d77be02246fa2b0b35d31fdf5e322b768fe4540c6cb7",
            x"2ba19937f08a10226c5b867ee8e40483c3b38bb7f33a08c55716d1f51ec7ddf2",
            x"c19c969095c742660a0559ad0e54418535701d089a207bb1ee0ebbb355fc565d",
            x"47563b28d0321fa66c12d6adff693542b3edbfba59b3f1a62371c26881c19def",
            x"cb15988fe2dfa06a6f774757996ff4f9559f7e1dca63fe08cf628a9855e919d9",
        ]
    }

    // skip.ops[1].l1.auth: top leaf 1. Levels 1..9 are shared with
    // ops[0].l1.auth (top leaves 0 and 1 are siblings); level 0 is top leaf 0.
    #[test_only]
    fun fixture_skip_b_l1_auth(): vector<vector<u8>> {
        let auth = fixture_op0_l1_auth();
        *vector::borrow_mut(&mut auth, 0) = FIXTURE_LEAF_L1_T0_0;
        auth
    }
}
