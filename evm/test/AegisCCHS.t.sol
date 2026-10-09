// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {AegisCCHSBase} from "../src/AegisCCHSBase.sol";
import {AegisCCHS} from "../src/AegisCCHS.sol";
import {AegisCCHSK} from "../src/AegisCCHSK.sol";
import {AegisCCHSFactory} from "../src/AegisCCHSFactory.sol";

/// @dev Verifies the contract against test vectors produced by the TypeScript
///      client (wallet/src/aegis/cchs.ts). The vectors bind chainId = 1 and a
///      fixed account address, so the contract is etched at that address and
///      its storage initialised directly.
///
///      Fixture: test/fixtures/cchs-s-20.json
abstract contract CCHSVectorTest is Test {
    string json;
    address acct;
    AegisCCHSBase a;
    address target;
    uint256 value;

    // storage slots in AegisCCHS
    uint256 constant SLOT_ROOT    = 0;
    uint256 constant SLOT_RECROOT = 1;

    function _fixture() internal pure virtual returns (string memory);
    function _runtime() internal pure virtual returns (bytes memory);

    function setUp() public {
        json = vm.readFile(string.concat(vm.projectRoot(), _fixture()));
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        acct   = vm.parseJsonAddress(json, ".account");
        target = vm.parseJsonAddress(json, ".ops[0].target");
        value  = vm.parseJsonUint(json, ".ops[0].value");

        vm.etch(acct, _runtime());
        vm.store(acct, bytes32(SLOT_ROOT),    vm.parseJsonBytes32(json, ".root"));
        vm.store(acct, bytes32(SLOT_RECROOT), vm.parseJsonBytes32(json, ".recRoot"));
        a = AegisCCHSBase(payable(acct));
        vm.deal(acct, 100 ether);

        assertEq(a.root(),    vm.parseJsonBytes32(json, ".root"));
        assertEq(a.recRoot(), vm.parseJsonBytes32(json, ".recRoot"));
        assertEq(a.nextIdx(0), 0);
    }

    // ------------------------------------------------------------ helpers

    function _layer(string memory path) internal view returns (AegisCCHSBase.LayerSig memory l) {
        bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(path, ".wots"));
        bytes32[] memory p = vm.parseJsonBytes32Array(json, string.concat(path, ".auth"));
        for (uint256 i; i < 67; ++i) l.wots[i] = w[i];
        for (uint256 i; i < 10; ++i) l.auth[i] = p[i];
    }

    function _op(uint256 i) internal view returns (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) {
        string memory p = string.concat(".ops[", vm.toString(i), "]");
        l0 = _layer(string.concat(p, ".l0"));
        hasL1 = vm.keyExistsJson(json, string.concat(p, ".l1.wots"));
        if (hasL1) l1 = _layer(string.concat(p, ".l1"));
    }

    function _exec(uint256 i) internal {
        (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _op(i);
        if (hasL1) a.executeFirst(target, value, "", uint64(i), l0, l1); else a.execute(target, value, "", uint64(i), l0);
    }

    function _skipOp(uint256 i) internal view returns (uint64 idx, AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) {
        string memory p = string.concat(".skip.ops[", vm.toString(i), "]");
        idx = uint64(vm.parseJsonUint(json, string.concat(p, ".idx")));
        l0 = _layer(string.concat(p, ".l0"));
        hasL1 = vm.keyExistsJson(json, string.concat(p, ".l1.wots"));
        if (hasL1) l1 = _layer(string.concat(p, ".l1"));
    }

    // ---------------------------------------------------------- vectors

    function test_digestMatchesClient() public view {
        assertEq(a.digestAt(a.nextIdx(0), target, value, ""), vm.parseJsonBytes32(json, ".ops[0].digest"));
    }

    function test_firstSigInSubtreeNeedsTopLayer() public {
        assertTrue(a.needsTopLayerAt(a.nextIdx(0)));
        (, bool hasL1, ) = _op(0);
        assertTrue(hasL1);
        _exec(0);
        assertEq(target.balance, value);
        assertEq(a.nextIdx(0), 1);
        assertEq(a.nonce(0), 1);
        assertFalse(a.needsTopLayerAt(a.nextIdx(0)));
        assertEq(a.cachedRoot(0), vm.parseJsonBytes32(json, ".bottomRoot0"));
    }

    function test_cachedPath() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _op(1);
        assertFalse(hasL1);
        uint256 g = gasleft();
        a.execute(target, value, "", 1, l0);
        emit log_named_uint("cached-path execution gas", g - gasleft());
        _exec(2);
        assertEq(target.balance, 3 * value);
        assertEq(a.nextIdx(0), 3);
    }

    function test_firstSigGas() public {
        (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _op(0);
        uint256 g = gasleft();
        a.executeFirst(target, value, "", 0, l0, l1);
        emit log_named_uint("first-in-subtree execution gas", g - gasleft());
    }

    // ---------------------------------------------------------- attacks

    function test_revert_missingTopLayerOnFreshSubtree() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.MissingTopLayer.selector);
        a.execute(target, value, "", 1, l0);
    }

    /// Mempool front-run: a valid signature replayed with a different target.
    function test_revert_frontRunDifferentTarget() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(address(0xDEAD), value, "", 1, l0);
    }

    function test_revert_frontRunDifferentValue() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value + 1, "", 1, l0);
    }

    /// Replay at the same index: rejected by the monotonic index check before
    /// any hashing. Replay at a later index: the digest differs, so the root
    /// does not match the cache.
    function test_revert_replay() public {
        _exec(0);
        _exec(1);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.execute(target, value, "", 1, l0);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value, "", 2, l0);
    }

    // ------------------------------------------------- signer-chosen index

    /// Skip leaves 1..4 inside the cached subtree, then jump to subtree 1.
    function test_skipWithinSubtreeAndAcrossSubtrees() public {
        _exec(0);
        (uint64 i5, AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _skipOp(0);
        assertEq(i5, 5);
        assertFalse(hasL1);
        assertEq(a.digestAt(i5, target, value, ""), vm.parseJsonBytes32(json, ".skip.ops[0].digest"));
        a.execute(target, value, "", i5, l0);
        assertEq(a.nextIdx(0), 6);
        assertEq(a.nonce(0), 2);

        (uint64 i1024, AegisCCHSBase.LayerSig memory m0, bool h1, AegisCCHSBase.LayerSig memory m1) = _skipOp(1);
        assertEq(i1024, 1024);
        assertTrue(h1);
        assertTrue(a.needsTopLayerAt(i1024));
        a.executeFirst(target, value, "", i1024, m0, m1);
        assertEq(a.nextIdx(0), 1025);
        assertEq(a.cachedRoot(1), vm.parseJsonBytes32(json, ".bottomRoot1"));
        assertEq(target.balance, 3 * value);
    }

    /// A transaction prepared with the top layer still succeeds if the subtree
    /// was registered in the meantime: the proof is ignored, not rejected.
    function test_executeFirstOnRegisteredSubtreeIgnoresProof() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , ) = _op(1);
        (, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        a.executeFirst(target, value, "", 1, l0, l1);
        assertEq(a.nextIdx(0), 2);
    }

    /// Jumping into a fresh subtree without its top layer is rejected.
    function test_revert_jumpToFreshSubtreeWithoutTopLayer() public {
        _exec(0);
        (uint64 i1024, AegisCCHSBase.LayerSig memory m0, , AegisCCHSBase.LayerSig memory empty) = _skipOp(1);
        vm.expectRevert(AegisCCHSBase.MissingTopLayer.selector);
        a.execute(target, value, "", i1024, m0);
    }

    /// A signature for leaf 5 cannot be used at leaf 6: the index is in the digest.
    function test_revert_signatureBoundToIndex() public {
        _exec(0);
        (, AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _skipOp(0);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value, "", 6, l0);
    }

    /// Abandoned leaves stay abandoned: after 0 -> 5 -> 1024, every leaf below
    /// 1025 is rejected before any hashing, used (1) or never used (6).
    function test_revert_backwardIndexAfterSkip() public {
        _exec(0);
        (uint64 i5, AegisCCHSBase.LayerSig memory l0, , ) = _skipOp(0);
        a.execute(target, value, "", i5, l0);
        (uint64 i1024, AegisCCHSBase.LayerSig memory m0, , AegisCCHSBase.LayerSig memory m1) = _skipOp(1);
        a.executeFirst(target, value, "", i1024, m0, m1);
        assertEq(a.nextIdx(0), 1025);

        (AegisCCHSBase.LayerSig memory l1, , ) = _op(1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.execute(target, value, "", 1, l1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.execute(target, value, "", 6, l1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.executeFirst(target, value, "", 1024, m0, m1);
    }

    /// Cache poisoning: genuine top-layer signature paired with a tampered
    /// bottom layer. r0' != r0, so the top chains do not close to `root`.
    function test_revert_cachePoisonWithTamperedBottom() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        l0.auth[0] = bytes32(uint256(l0.auth[0]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
        a.executeFirst(target, value, "", 0, l0, l1);
        assertEq(a.cachedRoot(0), bytes32(0));
    }

    function test_revert_tamperedWotsChain() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        l0.wots[7] = bytes32(uint256(l0.wots[7]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value, "", 1, l0);
    }

    function test_revert_wrongTopLayerSig() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        l1.wots[0] = bytes32(uint256(l1.wots[0]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
        a.executeFirst(target, value, "", 0, l0, l1);
    }

    // ------------------------------------------------------------- lanes

    function _laneOp() internal view returns (uint64 idx, AegisCCHSBase.LayerSig memory l0, AegisCCHSBase.LayerSig memory l1) {
        idx = uint64(vm.parseJsonUint(json, ".lane.ops[0].idx"));
        l0 = _layer(".lane.ops[0].l0");
        l1 = _layer(".lane.ops[0].l1");
    }

    /// Lane 1 starts at leaf 65 536 with its own nonce 0; its digest is the
    /// client's, and landing it leaves lane 0 untouched: op 0 (lane 0, nonce 0)
    /// is still valid afterwards, in either order.
    function test_lanesAreIndependent() public {
        (uint64 i, AegisCCHSBase.LayerSig memory l0, AegisCCHSBase.LayerSig memory l1) = _laneOp();
        assertEq(i, uint64(1) << 16);
        assertEq(a.laneOf(i), 1);
        assertEq(a.nextIdx(1), i);
        assertEq(a.nonce(1), 0);
        assertEq(a.digestAt(i, target, value, ""), vm.parseJsonBytes32(json, ".lane.ops[0].digest"));
        assertTrue(a.needsTopLayerAt(i));

        a.executeFirst(target, value, "", i, l0, l1);
        assertEq(a.nextIdx(1), i + 1);
        assertEq(a.nonce(1), 1);
        assertEq(a.cachedRoot(64), vm.parseJsonBytes32(json, ".lane.bottomRoot"));
        // lane 0 unchanged: still at 0 / nonce 0, op 0 lands as if nothing happened
        assertEq(a.nextIdx(0), 0);
        assertEq(a.nonce(0), 0);
        _exec(0);
        assertEq(a.nextIdx(0), 1);
        assertEq(a.nextIdx(1), i + 1);
        assertEq(target.balance, 2 * value);
    }

    function test_lanesIndependentOtherOrder() public {
        _exec(0);
        _exec(1);
        (uint64 i, AegisCCHSBase.LayerSig memory l0, AegisCCHSBase.LayerSig memory l1) = _laneOp();
        a.executeFirst(target, value, "", i, l0, l1);
        assertEq(a.nextIdx(0), 2);
        assertEq(a.nonce(0), 2);
        assertEq(a.nextIdx(1), i + 1);
        assertEq(a.nonce(1), 1);
    }

    /// A lane's index is monotone on its own: replay in lane 1 is IndexUsed
    /// even though lane 0 has moved, and lane 0's leaves are not abandoned by
    /// a spend in lane 1.
    function test_revert_laneReplay() public {
        (uint64 i, AegisCCHSBase.LayerSig memory l0, AegisCCHSBase.LayerSig memory l1) = _laneOp();
        a.executeFirst(target, value, "", i, l0, l1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.executeFirst(target, value, "", i, l0, l1);
        vm.expectRevert(AegisCCHSBase.IndexUsed.selector);
        a.execute(target, value, "", i, l0);
    }

    /// Untouched lanes read as their first leaf; lane 15 ends at 2^20 - 1.
    function test_laneViews() public view {
        for (uint8 l = 0; l < 16; ++l) {
            assertEq(a.nextIdx(l), uint64(l) << 16);
            assertEq(a.nonce(l), 0);
        }
        assertEq(a.laneOf((uint64(1) << 20) - 1), 15);
        assertEq(a.LANE_BITS(), 4);
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
        assertEq(a.nextIdx(0), 0);
        assertEq(a.nonce(0), 0);
        assertEq(a.recNonce(), 1);
        assertTrue(a.needsTopLayerAt(a.nextIdx(0)));
    }

    /// Recovery opens fresh lanes for every lane, not only lane 0.
    function test_recoverResetsAllLanes() public {
        (uint64 i, AegisCCHSBase.LayerSig memory l0, AegisCCHSBase.LayerSig memory l1) = _laneOp();
        a.executeFirst(target, value, "", i, l0, l1);
        _exec(0);
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        assertEq(a.nextIdx(1), i);
        assertEq(a.nonce(1), 0);
        assertEq(a.nextIdx(0), 0);
    }

    function test_revert_oldKeyAfterRecovery() public {
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
        a.executeFirst(target, value, "", 0, l0, l1);
    }

    function test_revert_recoverWrongRoots() public {
        (, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        vm.expectRevert(AegisCCHSBase.BadRecovery.selector);
        a.recover(keccak256("other"), newRec, w, p);
    }

    function test_revert_recoverReplay() public {
        (bytes32 newRoot, bytes32 newRec, bytes32[67] memory w, bytes32[8] memory p) = _recovery();
        a.recover(newRoot, newRec, w, p);
        vm.expectRevert(AegisCCHSBase.BadRecovery.selector);
        a.recover(newRoot, newRec, w, p);
    }
}


// ================================================================ suites

contract AegisCCHS_S20_Test is CCHSVectorTest {
    function _fixture() internal pure override returns (string memory) { return "/test/fixtures/cchs-s-20.json"; }
    function _runtime() internal pure override returns (bytes memory) { return type(AegisCCHS).runtimeCode; }
}

contract AegisCCHS_K20_Test is CCHSVectorTest {
    function _fixture() internal pure override returns (string memory) { return "/test/fixtures/cchs-k-20.json"; }
    function _runtime() internal pure override returns (bytes memory) { return type(AegisCCHSK).runtimeCode; }
}

// =============================================================== factory

contract AegisCCHSFactoryTest is Test {
    AegisCCHSFactory f;
    bytes32 constant ROOT = keccak256("root");
    bytes32 constant REC  = keccak256("rec");

    function setUp() public { f = new AegisCCHSFactory(); }

    function test_predictMatchesDeploy_S() public {
        address p = f.predict(ROOT, REC, true);
        address d = f.deploy(ROOT, REC, true);
        assertEq(d, p);
        assertEq(AegisCCHS(payable(d)).root(), ROOT);
        assertEq(AegisCCHS(payable(d)).recRoot(), REC);
        assertEq(keccak256(bytes(AegisCCHS(payable(d)).VERSION())), keccak256("cchs-s-20/1.0.0"));
    }

    function test_predictMatchesDeploy_K() public {
        address p = f.predict(ROOT, REC, false);
        address d = f.deploy(ROOT, REC, false);
        assertEq(d, p);
        assertEq(keccak256(bytes(AegisCCHSK(payable(d)).VERSION())), keccak256("cchs-k-20/1.0.0"));
    }

    function test_variantsGetDistinctAddresses() public view {
        assertTrue(f.predict(ROOT, REC, true) != f.predict(ROOT, REC, false));
    }

    function test_deployIsIdempotent() public {
        address a1 = f.deploy(ROOT, REC, false);
        address a2 = f.deploy(ROOT, REC, false);
        assertEq(a1, a2);
    }

    function test_revert_zeroRoot() public {
        vm.expectRevert(AegisCCHSBase.ZeroRoot.selector);
        f.deploy(bytes32(0), REC, false);
    }

    /// Same factory address + same (root, recRoot) => same account address on every chain.
    function test_addressIndependentOfChainId() public {
        address p1 = f.predict(ROOT, REC, false);
        vm.chainId(56);
        address p2 = f.predict(ROOT, REC, false);
        assertEq(p1, p2);
    }

    function test_deployForwardsValue() public {
        vm.deal(address(this), 3 ether);
        address a = f.deploy{value: 1 ether}(ROOT, REC, false);
        assertEq(a.balance, 1 ether);
        // funding an already-deployed account through the same call
        f.deploy{value: 2 ether}(ROOT, REC, false);
        assertEq(a.balance, 3 ether);
        assertEq(address(f).balance, 0);
    }

    function test_deployAndMovePullsTokens() public {
        MockToken t = new MockToken();
        t.mint(address(this), 500);
        t.approve(address(f), type(uint256).max);
        address[] memory toks = new address[](1);
        toks[0] = address(t);
        vm.deal(address(this), 1 ether);
        address a = f.deployAndMove{value: 0.5 ether}(ROOT, REC, false, toks);
        assertEq(t.balanceOf(a), 500);
        assertEq(t.balanceOf(address(this)), 0);
        assertEq(a.balance, 0.5 ether);
    }

    function test_deployAndMove_revertsWithoutApproval() public {
        MockToken t = new MockToken();
        t.mint(address(this), 500);
        address[] memory toks = new address[](1);
        toks[0] = address(t);
        vm.expectRevert(abi.encodeWithSelector(AegisCCHSFactory.TokenTransferFailed.selector, address(t)));
        f.deployAndMove(ROOT, REC, false, toks);
    }

    /// The account accepts ERC-721 and ERC-1155 safe transfers (any asset can be held).
    function test_accountAcceptsSafeTransfers() public {
        address a = f.deploy(ROOT, REC, false);
        MockNft nft = new MockNft();
        nft.mint(address(this), 7);
        nft.safeTransferFrom(address(this), a, 7);
        assertEq(nft.ownerOf(7), a);

        MockMultiToken mt = new MockMultiToken();
        mt.mint(address(this), 1, 10);
        mt.safeTransferFrom(address(this), a, 1, 10, "");
        assertEq(mt.balanceOf(1, a), 10);
        uint256[] memory ids = new uint256[](1); ids[0] = 1;
        uint256[] memory amts = new uint256[](1); amts[0] = 0;
        mt.safeBatchTransferFrom(address(this), a, ids, amts, "");

        AegisCCHSBase acct = AegisCCHSBase(payable(a));
        assertTrue(acct.supportsInterface(0x01ffc9a7));
        assertTrue(acct.supportsInterface(0x150b7a02));
        assertTrue(acct.supportsInterface(0x4e2312e0));
        assertFalse(acct.supportsInterface(0xffffffff));
    }
}

interface IERC721ReceiverLike { function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4); }
interface IERC1155ReceiverLike {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4);
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external returns (bytes4);
}

/// Minimal ERC-721 that enforces the receiver check exactly like OpenZeppelin.
contract MockNft {
    mapping(uint256 => address) public ownerOf;
    function mint(address to, uint256 id) external { ownerOf[id] = to; }
    function safeTransferFrom(address from, address to, uint256 id) external {
        require(ownerOf[id] == from && msg.sender == from, "nft: denied");
        ownerOf[id] = to;
        if (to.code.length > 0) {
            require(IERC721ReceiverLike(to).onERC721Received(msg.sender, from, id, "") == 0x150b7a02, "nft: unsafe recipient");
        }
    }
}

/// Minimal ERC-1155 with the receiver checks.
contract MockMultiToken {
    mapping(uint256 => mapping(address => uint256)) public balanceOf;
    function mint(address to, uint256 id, uint256 amt) external { balanceOf[id][to] += amt; }
    function safeTransferFrom(address from, address to, uint256 id, uint256 amt, bytes calldata data) external {
        require(msg.sender == from && balanceOf[id][from] >= amt, "mt: denied");
        balanceOf[id][from] -= amt; balanceOf[id][to] += amt;
        if (to.code.length > 0) {
            require(IERC1155ReceiverLike(to).onERC1155Received(msg.sender, from, id, amt, data) == 0xf23a6e61, "mt: unsafe recipient");
        }
    }
    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amts, bytes calldata data) external {
        require(msg.sender == from, "mt: denied");
        for (uint256 i = 0; i < ids.length; ++i) { balanceOf[ids[i]][from] -= amts[i]; balanceOf[ids[i]][to] += amts[i]; }
        if (to.code.length > 0) {
            require(IERC1155ReceiverLike(to).onERC1155BatchReceived(msg.sender, from, ids, amts, data) == 0xbc197c81, "mt: unsafe recipient");
        }
    }
}

contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function approve(address s, uint256 amt) external returns (bool) { allowance[msg.sender][s] = amt; return true; }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(allowance[from][msg.sender] >= amt && balanceOf[from] >= amt, "mock: denied");
        allowance[from][msg.sender] -= amt; balanceOf[from] -= amt; balanceOf[to] += amt;
        return true;
    }
}
