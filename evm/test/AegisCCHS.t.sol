// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {AegisCCHS} from "../src/AegisCCHS.sol";

/// @dev Self-contained Solidity reference signer (test-only) so the suite runs
///      without external vectors. Mirrors wallet/src/aegis/cchs.ts byte-for-byte.
///      Bottom/top trees are built at height 10 (1024 WOTS+ keys each), which is
///      ~1M sha256 calls per tree — fine under forge's default gas limit for tests.
contract CchsSigner {
    uint256 constant W = 16;
    uint256 constant LEN = 67;
    uint256 constant H = 10;
    uint256 constant REC_H = 8;

    bytes32 immutable master;
    constructor(bytes32 m) { master = m; }

    // --- HKDF-SHA256 (RFC 5869) with empty salt, 32-byte output ---
    function hkdf32(bytes memory info) internal view returns (bytes32) {
        bytes32 prk = hmac(bytes32(0), abi.encodePacked(master));
        return hmac(prk, abi.encodePacked(info, uint8(1)));
    }
    function hmac(bytes32 key, bytes memory data) internal pure returns (bytes32) {
        bytes memory k = new bytes(64);
        for (uint256 i = 0; i < 32; i++) k[i] = key[i];
        bytes memory ipad = new bytes(64);
        bytes memory opad = new bytes(64);
        for (uint256 i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
        return sha256(abi.encodePacked(opad, sha256(abi.encodePacked(ipad, data))));
    }

    function adrs(uint8 layer, uint64 treeIdx, uint8 typ, uint32 leafIdx, uint8 c, uint8 s) internal pure returns (bytes32) {
        return bytes32((uint256(layer) << 248) | (uint256(treeIdx) << 184) | (uint256(typ) << 176)
            | (uint256(leafIdx) << 144) | (uint256(c) << 136) | (uint256(s) << 128));
    }

    function sk(uint8 layer, uint64 treeIdx, uint32 leafIdx, uint8 c) internal view returns (bytes32) {
        return hkdf32(abi.encodePacked("cchs/sk", layer, treeIdx, leafIdx, c));
    }

    function digits(bytes32 m) public pure returns (uint8[67] memory d) {
        uint256 csum;
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(m[i]); uint8 hi = b >> 4; uint8 lo = b & 0x0f;
            d[2*i] = hi; d[2*i+1] = lo; csum += (W-1-hi) + (W-1-lo);
        }
        d[64] = uint8((csum >> 8) & 0x0f); d[65] = uint8((csum >> 4) & 0x0f); d[66] = uint8(csum & 0x0f);
    }

    function leaf(uint8 layer, uint64 treeIdx, uint32 leafIdx) public view returns (bytes32) {
        bytes memory pks = new bytes(LEN * 32);
        for (uint256 c = 0; c < LEN; c++) {
            bytes32 x = sk(layer, treeIdx, leafIdx, uint8(c));
            for (uint256 s = 0; s < W - 1; s++) x = sha256(abi.encodePacked(adrs(layer, treeIdx, 0, leafIdx, uint8(c), uint8(s)), x));
            assembly { mstore(add(add(pks, 32), mul(c, 32)), x) }
        }
        return sha256(abi.encodePacked(adrs(layer, treeIdx, 1, leafIdx, 0, 0), pks));
    }

    /// returns levels flattened: level k occupies [offset_k, offset_k + 2^(h-k))
    function tree(uint8 layer, uint64 treeIdx, uint256 h) public view returns (bytes32[] memory nodes) {
        uint256 n = 1 << h;
        nodes = new bytes32[](2 * n - 1);
        for (uint32 j = 0; j < n; j++) nodes[j] = leaf(layer, treeIdx, j);
        uint256 off = 0; uint256 width = n;
        for (uint256 k = 0; k < h; k++) {
            uint256 nextOff = off + width;
            for (uint256 i = 0; i < width / 2; i++) {
                nodes[nextOff + i] = sha256(abi.encodePacked(adrs(layer, treeIdx, 2, uint32(i), uint8(k), 0), nodes[off + 2*i], nodes[off + 2*i + 1]));
            }
            off = nextOff; width /= 2;
        }
    }

    function rootOf(bytes32[] memory nodes) public pure returns (bytes32) { return nodes[nodes.length - 1]; }

    function auth(bytes32[] memory nodes, uint256 h, uint32 leafIdx) public pure returns (bytes32[] memory path) {
        path = new bytes32[](h);
        uint256 off = 0; uint256 width = 1 << h; uint32 pos = leafIdx;
        for (uint256 k = 0; k < h; k++) {
            path[k] = nodes[off + (pos ^ 1)];
            off += width; width /= 2; pos >>= 1;
        }
    }

    function wotsSign(uint8 layer, uint64 treeIdx, uint32 leafIdx, bytes32 m) public view returns (bytes32[67] memory sig) {
        uint8[67] memory d = digits(m);
        for (uint256 c = 0; c < LEN; c++) {
            bytes32 x = sk(layer, treeIdx, leafIdx, uint8(c));
            for (uint256 s = 0; s < d[c]; s++) x = sha256(abi.encodePacked(adrs(layer, treeIdx, 0, leafIdx, uint8(c), uint8(s)), x));
            sig[c] = x;
        }
    }
}

contract AegisCCHSTest is Test {
    CchsSigner signer;
    AegisCCHS acct;

    bytes32[] topNodes;
    bytes32[] recNodes;
    bytes32[] bottom0;   // bottom tree 0

    address constant TARGET = address(0xBEEF);

    function setUp() public {
        signer = new CchsSigner(keccak256("aegis-cchs-test-master"));
        topNodes = signer.tree(1, 0, 10);
        recNodes = signer.tree(0xff, 0, 8);
        bottom0  = signer.tree(0, 0, 10);
        acct = new AegisCCHS(signer.rootOf(topNodes), signer.rootOf(recNodes));
        vm.deal(address(acct), 10 ether);
    }

    function _toFixed10(bytes32[] memory p) internal pure returns (bytes32[10] memory f) { for (uint256 i; i < 10; i++) f[i] = p[i]; }
    function _toFixed8(bytes32[] memory p) internal pure returns (bytes32[8] memory f) { for (uint256 i; i < 8; i++) f[i] = p[i]; }

    function _sig(uint64 idx, bytes32 m, bool withTop) internal view returns (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory l1) {
        uint64 treeIdx = idx >> 10; uint32 leafIdx = uint32(idx & 1023);
        require(treeIdx == 0, "test only covers bottom tree 0");
        l0.wots = signer.wotsSign(0, treeIdx, leafIdx, m);
        l0.auth = _toFixed10(signer.auth(bottom0, 10, leafIdx));
        if (withTop) {
            bytes32 r0 = signer.rootOf(bottom0);
            l1.wots = signer.wotsSign(1, 0, uint32(treeIdx), r0);
            l1.auth = _toFixed10(signer.auth(topNodes, 10, uint32(treeIdx)));
        }
    }

    function _exec(address target, uint256 value, bytes memory data, bool withTop) internal {
        bytes32 m = acct.nextDigest(target, value, data);
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory l1) = _sig(acct.nextIdx(), m, withTop);
        acct.execute(target, value, data, l0, withTop, l1);
    }

    // ---------------------------------------------------------------- happy

    function test_firstSigInSubtreeNeedsTopLayer() public {
        assertTrue(acct.needsTopLayer());
        _exec(TARGET, 1 ether, "", true);
        assertEq(TARGET.balance, 1 ether);
        assertEq(acct.nextIdx(), 1);
        assertFalse(acct.needsTopLayer());
        assertEq(acct.cachedRoot(0), signer.rootOf(bottom0));
    }

    function test_secondSigUsesCacheOnly() public {
        _exec(TARGET, 1 ether, "", true);
        uint256 g = gasleft();
        _exec(TARGET, 1 ether, "", false);
        uint256 used = g - gasleft();
        emit log_named_uint("cached-path gas", used);
        assertEq(TARGET.balance, 2 ether);
        assertEq(acct.nextIdx(), 2);
    }

    function test_firstSigGas() public {
        uint256 g = gasleft();
        _exec(TARGET, 1 ether, "", true);
        emit log_named_uint("first-in-subtree gas", g - gasleft());
    }

    // -------------------------------------------------------------- attacks

    function test_revert_missingTopLayerOnFreshSubtree() public {
        bytes32 m = acct.nextDigest(TARGET, 1 ether, "");
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory empty) = _sig(0, m, false);
        vm.expectRevert(AegisCCHS.MissingTopLayer.selector);
        acct.execute(TARGET, 1 ether, "", l0, false, empty);
    }

    /// Mempool front-run: attacker takes a valid signature for (TARGET, 1 ether)
    /// and replays it with a different target. Digest differs → chains don't close.
    function test_revert_frontRunDifferentTarget() public {
        _exec(TARGET, 1 ether, "", true);
        bytes32 m = acct.nextDigest(TARGET, 1 ether, "");
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory empty) = _sig(1, m, false);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        acct.execute(address(0xDEAD), 1 ether, "", l0, false, empty);
    }

    /// Replay: same valid signature twice. nextIdx moved → digest differs.
    function test_revert_replay() public {
        bytes32 m = acct.nextDigest(TARGET, 1 ether, "");
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory l1) = _sig(0, m, true);
        acct.execute(TARGET, 1 ether, "", l0, true, l1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        acct.execute(TARGET, 1 ether, "", l0, true, l1);
    }

    /// Cache poisoning: attacker tries to register a fake bottom root with a
    /// top-layer signature they don't have. Reuses the genuine l1 (signed on the
    /// real r0) against a tampered l0 → r0' ≠ r0 → top chains don't close.
    function test_revert_cachePoisonWithTamperedBottom() public {
        bytes32 m = acct.nextDigest(TARGET, 1 ether, "");
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory l1) = _sig(0, m, true);
        l0.auth[0] = bytes32(uint256(l0.auth[0]) ^ 1);
        vm.expectRevert(AegisCCHS.BadTopRoot.selector);
        acct.execute(TARGET, 1 ether, "", l0, true, l1);
        assertEq(acct.cachedRoot(0), bytes32(0));
    }

    function test_revert_tamperedWotsChain() public {
        _exec(TARGET, 1 ether, "", true);
        bytes32 m = acct.nextDigest(TARGET, 1 ether, "");
        (AegisCCHS.LayerSig memory l0, AegisCCHS.LayerSig memory empty) = _sig(1, m, false);
        l0.wots[7] = bytes32(uint256(l0.wots[7]) ^ 1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        acct.execute(TARGET, 1 ether, "", l0, false, empty);
    }

    // ------------------------------------------------------------- recovery

    function test_recoverRotatesRootsAndBumpsEpoch() public {
        _exec(TARGET, 1 ether, "", true);
        bytes32 newRoot = keccak256("new-root");
        bytes32 newRec  = keccak256("new-rec");
        bytes32 m = sha256(abi.encodePacked("AEGIS_CCHS_RECOVER_V1", block.chainid, address(acct), uint64(0), newRoot, newRec));
        bytes32[67] memory w = signer.wotsSign(0xff, 0, 0, m);
        bytes32[8] memory a = _toFixed8(signer.auth(recNodes, 8, 0));
        acct.recover(newRoot, newRec, w, a);
        assertEq(acct.root(), newRoot);
        assertEq(acct.recRoot(), newRec);
        assertEq(acct.epoch(), 1);
        assertEq(acct.nextIdx(), 0);
        assertEq(acct.recNonce(), 1);
        // old cache is namespaced by epoch 0; epoch 1 sees nothing.
        assertTrue(acct.needsTopLayer());
    }

    function test_revert_recoverWithWrongDigest() public {
        bytes32 newRoot = keccak256("new-root");
        bytes32 m = sha256("wrong");
        bytes32[67] memory w = signer.wotsSign(0xff, 0, 0, m);
        bytes32[8] memory a = _toFixed8(signer.auth(recNodes, 8, 0));
        vm.expectRevert(AegisCCHS.BadRecovery.selector);
        acct.recover(newRoot, keccak256("x"), w, a);
    }
}
