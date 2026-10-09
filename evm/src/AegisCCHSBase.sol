// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AegisCCHSBase — Chain-Cached Hypertree Signature account, hash-agnostic core.
/// @notice Hash-only post-quantum account. Authorization is a WOTS+ signature
///         (w=16, 67 chains) under a two-layer hypertree of height 10+10
///         (2^20 signatures). The top-layer proof for each bottom subtree is
///         verified once and cached in `cachedRoot`; the following 1023
///         signatures in that subtree carry only the bottom layer.
///
///         Spec: ../../CCHS.spec.md
///
/// @dev    Concrete contracts supply the hash: `AegisCCHS` (SHA-256, parameter
///         set CCHS-S-20, byte-compatible with every other chain) and
///         `AegisCCHSK` (keccak256, CCHS-K-20, ~6x cheaper on the EVM).
///         Client is stateless: it reads `nextIdx` and `nonce` from chain and
///         derives everything from a 32-byte master seed.
abstract contract AegisCCHSBase {
    // ---------------------------------------------------------------- params
    uint256 internal constant W      = 16;
    uint256 internal constant LEN    = 67;   // 64 message + 3 checksum chains
    uint256 internal constant H      = 10;   // tree height per layer
    uint256 internal constant LEAVES = 1 << H;
    uint256 internal constant REC_H  = 8;

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
    error IndexUsed();
    error BadSubtreeRoot();
    error MissingTopLayer();
    error BadTopRoot();
    error BadRecovery();
    error CallFailed();
    error ZeroRoot();
    error AlreadyInitialized();

    // --------------------------------------------------------------- init
    /// @dev Called by the constructor of the concrete contract or by a factory
    ///      using a minimal-proxy pattern. Storage is zero before init.
    function _init(bytes32 _root, bytes32 _recRoot) internal {
        if (root != bytes32(0)) revert AlreadyInitialized();
        if (_root == bytes32(0) || _recRoot == bytes32(0)) revert ZeroRoot();
        root    = _root;
        recRoot = _recRoot;
    }

    receive() external payable {}

    // ===================================================== token receivers
    // The account holds any asset: ETH through `receive`, ERC-20 by plain
    // transfer, ERC-721 / ERC-1155 through the safe-transfer callbacks below.
    // Spending any of them is one `execute` call authorized by a CCHS signature.

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xf23a6e61;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external pure returns (bytes4)
    {
        return 0xbc197c81;
    }

    /// @notice ERC-165: IERC165, IERC721Receiver, IERC1155Receiver.
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == 0x150b7a02 || id == 0x4e2312e0;
    }

    // ============================================================ hash hooks

    /// @dev Generic hash of a memory buffer (digests, recovery messages).
    function _hash(bytes memory data) internal view virtual returns (bytes32);

    /// @dev From a WOTS+ signature on `m`, complete every chain to its end and
    ///      compress the 67 chain ends into the leaf hash. Hot path.
    function _wotsLeaf(
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal view virtual returns (bytes32 leaf);

    /// @dev Merkle node hash with child order chosen by `odd` (position parity).
    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal view virtual returns (bytes32 out);

    // ============================================================= execute

    /// @notice Execute `target.call{value}(data)` authorized by a CCHS signature.
    /// @param idx    Leaf index the signer chose. Must be `>= nextIdx`; indices
    ///               below `idx` are abandoned forever (`nextIdx` becomes
    ///               `idx + 1`). Skipping is how a signer leaves behind a leaf
    ///               whose signature was broadcast but never landed, or an
    ///               entire subtree whose keys it no longer trusts. Only the
    ///               signer can skip, because `idx` is bound into the digest.
    /// @param l0     Bottom-layer WOTS+ signature + auth path for leaf `idx`.
    /// @dev   Cached path: the subtree of `idx` must already be registered.
    ///        Carrying only one layer keeps calldata at 2.5 KB; use
    ///        `executeFirst` for the first operation in a subtree.
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 idx,
        LayerSig calldata l0
    ) external returns (bytes memory result) {
        bytes32 m = _begin(idx, target, value, data);
        bytes32 r0 = _layerRoot(0, idx >> H, uint32(idx & (LEAVES - 1)), m, l0);
        bytes32 cached = cachedRoot[_cacheKey(idx >> H)];
        if (cached == bytes32(0)) revert MissingTopLayer();
        if (cached != r0) revert BadSubtreeRoot();
        return _finish(idx, target, value, data);
    }

    /// @notice `execute` with the top-layer proof for the subtree of `idx`.
    ///         Registers the subtree root (once) and runs the call. If the
    ///         subtree is already registered the proof is ignored, so a
    ///         transaction prepared before another registration landed still
    ///         succeeds.
    /// @param l1     Top-layer WOTS+ signature on the bottom subtree root + auth path.
    function executeFirst(
        address target,
        uint256 value,
        bytes calldata data,
        uint64 idx,
        LayerSig calldata l0,
        LayerSig calldata l1
    ) external returns (bytes memory result) {
        bytes32 m = _begin(idx, target, value, data);
        uint64 treeIdx = idx >> H;
        bytes32 r0 = _layerRoot(0, treeIdx, uint32(idx & (LEAVES - 1)), m, l0);
        uint256 key = _cacheKey(treeIdx);
        bytes32 cached = cachedRoot[key];
        if (cached != bytes32(0)) {
            if (cached != r0) revert BadSubtreeRoot();
        } else {
            // Top layer: tree 0, leaf = treeIdx, message = r0.
            if (_layerRoot(1, 0, uint32(treeIdx), r0, l1) != root) revert BadTopRoot();
            cachedRoot[key] = r0;
            emit SubtreeCached(epoch, treeIdx, r0);
        }
        return _finish(idx, target, value, data);
    }

    /// @dev Index discipline shared by both entry points, then the digest.
    function _begin(uint64 idx, address target, uint256 value, bytes calldata data)
        internal view returns (bytes32)
    {
        if (idx < nextIdx) revert IndexUsed();
        if (idx >= (1 << (2 * H))) revert Exhausted();
        return _digest(idx, target, value, data);
    }

    /// @dev State update (effects) then the call (interaction).
    function _finish(uint64 idx, address target, uint256 value, bytes calldata data)
        internal returns (bytes memory result)
    {
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
        if (rn >= (1 << REC_H)) revert Exhausted();

        bytes32 m = _hash(
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
        for (uint256 k = 0; k < REC_H; ++k) {
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

    /// @dev M = hash("AEGIS_CCHS_V1" ‖ chainId ‖ this ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data))
    function _digest(uint64 idx, address target, uint256 value, bytes calldata data)
        internal view returns (bytes32)
    {
        return _hash(
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

    /// @dev `cachedRoot` key: (epoch << 64) | bottomTreeIdx.
    function _cacheKey(uint64 treeIdx) internal view returns (uint256) {
        return (uint256(epoch) << 64) | treeIdx;
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

    /// @notice Digest the client must sign for an `execute` at leaf `idx`
    ///         (`idx >= nextIdx`) with the current nonce.
    function digestAt(uint64 idx, address target, uint256 value, bytes calldata data)
        external view returns (bytes32)
    {
        return _digest(idx, target, value, data);
    }

    /// @notice Digest for an `execute` at `nextIdx`.
    function nextDigest(address target, uint256 value, bytes calldata data)
        external view returns (bytes32)
    {
        return _digest(nextIdx, target, value, data);
    }

    /// @notice Whether an `execute` at leaf `idx` must include the top-layer proof.
    function needsTopLayerAt(uint64 idx) public view returns (bool) {
        return cachedRoot[_cacheKey(idx >> H)] == bytes32(0);
    }

    /// @notice Whether an `execute` at `nextIdx` must include the top-layer proof.
    function needsTopLayer() external view returns (bool) {
        return needsTopLayerAt(nextIdx);
    }
}
