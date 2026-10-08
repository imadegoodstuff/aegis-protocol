// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {AegisCCHS} from "../src/AegisCCHS.sol";

/// @dev Verifies the contract against test vectors produced by the TypeScript
///      client (wallet/src/aegis/cchs.ts). The vectors bind chainId = 1 and a
///      fixed account address, so the contract is etched at that address and
///      its storage initialised directly.
///
///      Fixture: test/fixtures/cchs-s-20.json
contract AegisCCHSTest is Test {
    string json;
    address acct;
    AegisCCHS a;
    address target;
    uint256 value;

    // storage slots in AegisCCHS
    uint256 constant SLOT_ROOT    = 0;
    uint256 constant SLOT_RECROOT = 1;

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/cchs-s-20.json"));
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        acct   = vm.parseJsonAddress(json, ".account");
        target = vm.parseJsonAddress(json, ".ops[0].target");
        value  = vm.parseJsonUint(json, ".ops[0].value");

        vm.etch(acct, type(AegisCCHS).runtimeCode);
        vm.store(acct, bytes32(SLOT_ROOT),    vm.parseJsonBytes32(json, ".root"));
        vm.store(acct, bytes32(SLOT_RECROOT), vm.parseJsonBytes32(json, ".recRoot"));
        a = AegisCCHS(payable(acct));
        vm.deal(acct, 100 ether);

        assertEq(a.root(),    vm.parseJsonBytes32(json, ".root"));
        assertEq(a.recRoot(), vm.parseJsonBytes32(json, ".recRoot"));
        assertEq(a.nextIdx(), 0);
    }

    // ------------------------------------------------------------ helpers

    function _layer(string memory path) internal view returns (AegisCCHS.LayerSig memory l) {
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(path, ".wots"));
        bytes32[] memory p = vm.parseJsonBytes32Array(json, string.concat(path, ".auth"));
        for (uint256 i; i < 67; ++i) l.wots[i] = w[i];
        for (uint256 i; i < 10; ++i) l.auth[i] = p[i];
    }

    function _op(uint256 i) internal view returns (AegisCCHS.LayerSig memory l0, bool hasL1, AegisCCHS.LayerSig memory l1) {
        string memory p = string.concat(".ops[", vm.toString(i), "]");
        l0 = _layer(string.concat(p, ".l0"));
        hasL1 = vm.keyExistsJson(json, string.concat(p, ".l1.wots"));
        if (hasL1) l1 = _layer(string.concat(p, ".l1"));
    }

    function _exec(uint256 i) internal {
        (AegisCCHS.LayerSig memory l0, bool hasL1, AegisCCHS.LayerSig memory l1) = _op(i);
        a.execute(target, value, "", l0, hasL1, l1);
    }

    // ---------------------------------------------------------- vectors

    function test_digestMatchesClient() public view {
        assertEq(a.nextDigest(target, value, ""), vm.parseJsonBytes32(json, ".ops[0].digest"));
    }

    function test_firstSigInSubtreeNeedsTopLayer() public {
        assertTrue(a.needsTopLayer());
        (, bool hasL1, ) = _op(0);
        assertTrue(hasL1);
        _exec(0);
        assertEq(target.balance, value);
        assertEq(a.nextIdx(), 1);
        assertEq(a.nonce(), 1);
        assertFalse(a.needsTopLayer());
        assertEq(a.cachedRoot(0), vm.parseJsonBytes32(json, ".bottomRoot0"));
    }

    function test_cachedPath() public {
        _exec(0);
        (AegisCCHS.LayerSig memory l0, bool hasL1, AegisCCHS.LayerSig memory l1) = _op(1);
        assertFalse(hasL1);
        uint256 g = gasleft();
        a.execute(target, value, "", l0, hasL1, l1);
        emit log_named_uint("cached-path execution gas", g - gasleft());
        _exec(2);
        assertEq(target.balance, 3 * value);
        assertEq(a.nextIdx(), 3);
    }

    function test_firstSigGas() public {
        (AegisCCHS.LayerSig memory l0, bool hasL1, AegisCCHS.LayerSig memory l1) = _op(0);
        uint256 g = gasleft();
        a.execute(target, value, "", l0, hasL1, l1);
        emit log_named_uint("first-in-subtree execution gas", g - gasleft());
    }

    // ---------------------------------------------------------- attacks

    function test_revert_missingTopLayerOnFreshSubtree() public {
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHS.MissingTopLayer.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    /// Mempool front-run: a valid signature replayed with a different target.
    function test_revert_frontRunDifferentTarget() public {
        _exec(0);
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        a.execute(address(0xDEAD), value, "", l0, false, empty);
    }

    function test_revert_frontRunDifferentValue() public {
        _exec(0);
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        a.execute(target, value + 1, "", l0, false, empty);
    }

    function test_revert_replay() public {
        _exec(0);
        _exec(1);
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    /// Cache poisoning: genuine top-layer signature paired with a tampered
    /// bottom layer. r0' != r0, so the top chains do not close to `root`.
    function test_revert_cachePoisonWithTamperedBottom() public {
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory l1) = _op(0);
        l0.auth[0] = bytes32(uint256(l0.auth[0]) ^ 1);
        vm.expectRevert(AegisCCHS.BadTopRoot.selector);
        a.execute(target, value, "", l0, true, l1);
        assertEq(a.cachedRoot(0), bytes32(0));
    }

    function test_revert_tamperedWotsChain() public {
        _exec(0);
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory empty) = _op(1);
        l0.wots[7] = bytes32(uint256(l0.wots[7]) ^ 1);
        vm.expectRevert(AegisCCHS.BadSubtreeRoot.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    function test_revert_wrongTopLayerSig() public {
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory l1) = _op(0);
        l1.wots[0] = bytes32(uint256(l1.wots[0]) ^ 1);
        vm.expectRevert(AegisCCHS.BadTopRoot.selector);
        a.execute(target, value, "", l0, true, l1);
    }

    // --------------------------------------------------------- recovery

    function _recovery() internal view returns (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) {
        newRoot = vm.parseJsonBytes32(json, ".recovery.newRoot");
        newRec  = vm.parseJsonBytes32(json, ".recovery.newRecRoot");
        bytes32[] memory ww = vm.parseJsonBytes32Array(json, ".recovery.wots");
        bytes32[] memory pp = vm.parseJsonBytes32Array(json, ".recovery.auth");
        for (uint256 i; i < 67; ++i) w[i] = ww[i];
        for (uint256 i; i < 8; ++i) p[i] = pp[i];
    }

    function test_recoverRotatesRootsAndBumpsEpoch() public {
        _exec(0);
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        assertEq(a.root(), newRoot);
        assertEq(a.recRoot(), newRec);
        assertEq(a.epoch(), 1);
        assertEq(a.nextIdx(), 0);
        assertEq(a.recNonce(), 1);
        assertTrue(a.needsTopLayer());
    }

    function test_revert_oldKeyAfterRecovery() public {
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        (AegisCCHS.LayerSig memory l0, , AegisCCHS.LayerSig memory l1) = _op(0);
        vm.expectRevert(AegisCCHS.BadTopRoot.selector);
        a.execute(target, value, "", l0, true, l1);
    }

    function test_revert_recoverWrongRoots() public {
        (, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        vm.expectRevert(AegisCCHS.BadRecovery.selector);
        a.recover(keccak256("other"), newRec, w, p);
    }

    function test_revert_recoverReplay() public {
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        vm.expectRevert(AegisCCHS.BadRecovery.selector);
        a.recover(newRoot, newRec, w, p);
    }
}
