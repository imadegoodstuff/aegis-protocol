// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AegisCCHS — Chain-Cached Hypertree Signature account (CCHS-S-20).
/// @notice Hash-only post-quantum account. Authorization is a WOTS+ signature
///         (w=16, 67 chains, SHA-256) under a two-layer hypertree of height
///         10+10 (2^20 signatures). The top-layer proof for each bottom subtree
///         is verified once and cached in `cachedRoot`; the following 1023
///         signatures in that subtree carry only the bottom layer.
///
///         Spec: ../../CCHS.spec.md
///
/// @dev    Only SHA-256 is used. No ECDSA, no lattice, no external verifier.
///         Client is stateless: it reads `nextIdx` and `nonce` from chain and
///         derives everything from a 32-byte master seed.
contract AegisCCHS {
    // ---------------------------------------------------------------- params
    string  public constant VERSION = "cchs-s-20/1.0.0";
    uint256 internal constant W      = 16;
    uint256 internal constant LEN    = 67;   // 64 message + 3 checksum chains
    uint256 internal constant H      = 10;   // tree height per layer
    uint256 internal constant LEAVES = 1 << H;

    // --------------------------------------------------------------- storage
    /// @notice Top-layer tree root. Rotatable only via `recover`.
    bytes32 public root;
    /// @notice Recovery tree root (single layer, height 8).
    bytes32 public recRoot;
    /// @notice Epoch increments on every recovery; namespaces `cachedRoot`.
    uint64  public epoch;
    /// @notice Next unused leaf index in [0, 2^20).
    uint64  public nextIdx;
    /// @notice Transaction nonce bound into every message digest.
    uint64  public nonce;
    /// @notice Next unused recovery leaf in [0, 256).
    uint64  public recNonce;

    /// @dev key = (epoch << 64) | bottomTreeIdx
    mapping(uint256 => bytes32) public cachedRoot;

    // ---------------------------------------------------------------- types
    struct LayerSig {
        bytes32[67] wots;   // one chain value per WOTS+ chain
        bytes32[10] auth;   // Merkle authentication path, leaf → root
    }

    // --------------------------------------------------------------- events
    event Executed(uint64 indexed idx, address indexed target, uint256 value);
    event SubtreeCached(uint64 indexed epoch, uint64 indexed treeIdx, bytes32 subtreeRoot);
    event Recovered(uint64 indexed newEpoch, bytes32 newRoot, bytes32 newRecRoot);

    // --------------------------------------------------------------- errors
    error Exhausted();
    error BadSubtreeRoot();
    error MissingTopLayer();
    error BadTopRoot();
    error BadRecovery();
    error CallFailed();
    error ZeroRoot();

    // --------------------------------------------------------------- ctor
    constructor(bytes32 _root, bytes32 _recRoot) {
        if (_root == bytes32(0) || _recRoot == bytes32(0)) revert ZeroRoot();
        root    = _root;
        recRoot = _recRoot;
    }

    receive() external payable {}

    // ============================================================= execute

    /// @notice Execute `target.call{value}(data)` authorized by a CCHS signature.
    /// @param l0       Bottom-layer WOTS+ signature + auth path for leaf `nextIdx`.
    /// @param hasL1    True if the top-layer proof is included (first use of a subtree).
    /// @param l1       Top-layer WOTS+ signature on the bottom subtree root + auth path.
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        LayerSig calldata l0,
        bool hasL1,
        LayerSig calldata l1
    ) external returns (bytes memory result) {
        uint64 idx = nextIdx;
        if (idx >= (1 << (2 * H))) revert Exhausted();

        bytes32 m = _digest(idx, target, value, data);
        _verifyAndCache(idx, m, l0, hasL1, l1);

        // --- effects before interaction ---
        unchecked {
            nextIdx = idx + 1;
            nonce  += 1;
        }

        bool ok;
        (ok, result) = target.call{value: value}(data);
        if (!ok) revert CallFailed();
        emit Executed(idx, target, value);
    }

    // ============================================================ recovery

    /// @notice Rotate `root` and `recRoot`, authorized by the recovery tree.
    ///         Resets `nextIdx` and bumps `epoch` (logically clearing the cache).
    function recover(
        bytes32 newRoot,
        bytes32 newRecRoot,
        bytes32[67] calldata wots,
        bytes32[8]  calldata auth
    ) external {
        if (newRoot == bytes32(0) || newRecRoot == bytes32(0)) revert ZeroRoot();
        uint64 rn = recNonce;
        if (rn >= 256) revert Exhausted();

        bytes32 m = sha256(
            abi.encodePacked(
                "AEGIS_CCHS_RECOVER_V1",
                block.chainid,
                address(this),
                rn,
                newRoot,
                newRecRoot
            )
        );

        // layer id 0xFF marks the recovery tree in ADRS.
        bytes32 r = _wotsLeaf(0xFF, 0, uint32(rn), m, wots);
        uint32 pos = uint32(rn);
        for (uint256 k = 0; k < 8; ++k) {
            r = _node(_adrs(0xFF, 0, 0x02, uint32(pos >> 1), uint8(k), 0), r, auth[k], pos & 1);
            pos >>= 1;
        }
        if (r != recRoot) revert BadRecovery();

        root    = newRoot;
        recRoot = newRecRoot;
        nextIdx = 0;
        unchecked {
            epoch    += 1;
            recNonce  = rn + 1;
        }
        emit Recovered(epoch, newRoot, newRecRoot);
    }

    // ============================================================ internals

    /// @dev M = sha256("AEGIS_CCHS_V1" ‖ chainId ‖ this ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data))
    function _digest(uint64 idx, address target, uint256 value, bytes calldata data)
        internal view returns (bytes32)
    {
        return sha256(
            abi.encodePacked(
                "AEGIS_CCHS_V1",
                block.chainid,
                address(this),
                nonce,
                idx,
                target,
                value,
                keccak256(data)
            )
        );
    }

    /// @dev Layer-0 verification, then either cache equality or full top-layer
    ///      verification with cache write. Reverts on any mismatch.
    function _verifyAndCache(
        uint64 idx,
        bytes32 m,
        LayerSig calldata l0,
        bool hasL1,
        LayerSig calldata l1
    ) internal {
        uint64 treeIdx = idx >> H;
        bytes32 r0 = _layerRoot(0, treeIdx, uint32(idx & (LEAVES - 1)), m, l0);

        uint256 key = (uint256(epoch) << 64) | treeIdx;
        bytes32 cached = cachedRoot[key];
        if (cached != bytes32(0)) {
            if (cached != r0) revert BadSubtreeRoot();
            return;
        }
        if (!hasL1) revert MissingTopLayer();
        // Top layer: tree 0, leaf = treeIdx, message = r0.
        if (_layerRoot(1, 0, uint32(treeIdx), r0, l1) != root) revert BadTopRoot();
        cachedRoot[key] = r0;
        emit SubtreeCached(epoch, treeIdx, r0);
    }

    /// @dev Recompute the root of tree (`layer`, `treeIdx`) from a WOTS+
    ///      signature on `m` at `leafIdx` and the auth path.
    function _layerRoot(
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        LayerSig calldata s
    ) internal view returns (bytes32 r) {
        r = _wotsLeaf(layer, treeIdx, leafIdx, m, s.wots);
        uint32 pos = leafIdx;
        for (uint256 k = 0; k < H; ++k) {
            r = _node(_adrs(layer, treeIdx, 0x02, uint32(pos >> 1), uint8(k), 0), r, s.auth[k], pos & 1);
            pos >>= 1;
        }
    }

    /// @dev From a WOTS+ signature on `m`, complete every chain to its end
    ///      and compress the 67 chain ends into the leaf hash.
    ///      Hot loop in assembly: one SHA-256 precompile staticcall per step,
    ///      scratch memory reused, no abi.encodePacked allocations.
    function _wotsLeaf(
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal view returns (bytes32 leaf) {
        uint8[67] memory digits = _digits(m);
        // ADRS with chainIdx = step = 0; per-chain and per-step bytes OR'd in.
        bytes32 base = _adrs(layer, treeIdx, 0x00, leafIdx, 0, 0);
        bytes32 leafAdrs = _adrs(layer, treeIdx, 0x01, leafIdx, 0, 0);

        assembly {
            // buf: [leafAdrs][pk_0]...[pk_66]  = 32 + 67*32 bytes
            let buf := mload(0x40)
            mstore(0x40, add(buf, 2176))
            mstore(buf, leafAdrs)

            for { let c := 0 } lt(c, 67) { c := add(c, 1) } {
                let x := calldataload(add(sig, mul(c, 32)))
                let adrsC := or(base, shl(136, c))
                let start := mload(add(digits, mul(c, 32)))
                for { let s := start } lt(s, 15) { s := add(s, 1) } {
                    // scratch 0x00..0x3f: adrs ‖ x
                    mstore(0x00, or(adrsC, shl(128, s)))
                    mstore(0x20, x)
                    if iszero(staticcall(gas(), 0x02, 0x00, 64, 0x00, 32)) { revert(0, 0) }
                    x := mload(0x00)
                }
                mstore(add(buf, add(32, mul(c, 32))), x)
            }

            if iszero(staticcall(gas(), 0x02, buf, 2176, 0x00, 32)) { revert(0, 0) }
            leaf := mload(0x00)
        }
    }

    /// @dev T_node(adrs, l, r) with child order chosen by `odd` (position parity).
    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal view returns (bytes32 out)
    {
        assembly {
            let p := mload(0x40)
            mstore(p, adrs)
            switch odd
            case 0 { mstore(add(p, 32), cur) mstore(add(p, 64), sib) }
            default { mstore(add(p, 32), sib) mstore(add(p, 64), cur) }
            if iszero(staticcall(gas(), 0x02, p, 96, 0x00, 32)) { revert(0, 0) }
            out := mload(0x00)
        }
    }

    /// @dev 64 base-16 message digits followed by 3 base-16 checksum digits.
    function _digits(bytes32 m) internal pure returns (uint8[67] memory d) {
        uint256 csum = 0;
        for (uint256 i = 0; i < 32; ++i) {
            uint8 b = uint8(m[i]);
            uint8 hi = b >> 4;
            uint8 lo = b & 0x0f;
            d[2 * i]     = hi;
            d[2 * i + 1] = lo;
            csum += (W - 1 - hi) + (W - 1 - lo);
        }
        // csum ≤ 64 * 15 = 960 < 16^3; encode as 3 big-endian base-16 digits.
        d[64] = uint8((csum >> 8) & 0x0f);
        d[65] = uint8((csum >> 4) & 0x0f);
        d[66] = uint8(csum & 0x0f);
    }

    /// @dev ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pad(16)
    function _adrs(
        uint8 layer,
        uint64 treeIdx,
        uint8 typ,
        uint32 leafIdx,
        uint8 chainIdx,
        uint8 step
    ) internal pure returns (bytes32) {
        return bytes32(
            (uint256(layer)    << 248) |
            (uint256(treeIdx)  << 184) |
            (uint256(typ)      << 176) |
            (uint256(leafIdx)  << 144) |
            (uint256(chainIdx) << 136) |
            (uint256(step)     << 128)
        );
    }

    // ============================================================== views

    /// @notice Digest the client must sign for the next `execute`.
    function nextDigest(address target, uint256 value, bytes calldata data)
        external view returns (bytes32)
    {
        return _digest(nextIdx, target, value, data);
    }

    /// @notice Whether the next `execute` must include the top-layer proof.
    function needsTopLayer() external view returns (bool) {
        return cachedRoot[(uint256(epoch) << 64) | (nextIdx >> H)] == bytes32(0);
    }
}
