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
        assertEq(a.nextIdx(), 0);
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
        (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _op(1);
        assertFalse(hasL1);
        uint256 g = gasleft();
        a.execute(target, value, "", l0, hasL1, l1);
        emit log_named_uint("cached-path execution gas", g - gasleft());
        _exec(2);
        assertEq(target.balance, 3 * value);
        assertEq(a.nextIdx(), 3);
    }

    function test_firstSigGas() public {
        (AegisCCHSBase.LayerSig memory l0, bool hasL1, AegisCCHSBase.LayerSig memory l1) = _op(0);
        uint256 g = gasleft();
        a.execute(target, value, "", l0, hasL1, l1);
        emit log_named_uint("first-in-subtree execution gas", g - gasleft());
    }

    // ---------------------------------------------------------- attacks

    function test_revert_missingTopLayerOnFreshSubtree() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.MissingTopLayer.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    /// Mempool front-run: a valid signature replayed with a different target.
    function test_revert_frontRunDifferentTarget() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(address(0xDEAD), value, "", l0, false, empty);
    }

    function test_revert_frontRunDifferentValue() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value + 1, "", l0, false, empty);
    }

    function test_revert_replay() public {
        _exec(0);
        _exec(1);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    /// Cache poisoning: genuine top-layer signature paired with a tampered
    /// bottom layer. r0' != r0, so the top chains do not close to `root`.
    function test_revert_cachePoisonWithTamperedBottom() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        l0.auth[0] = bytes32(uint256(l0.auth[0]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
        a.execute(target, value, "", l0, true, l1);
        assertEq(a.cachedRoot(0), bytes32(0));
    }

    function test_revert_tamperedWotsChain() public {
        _exec(0);
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory empty) = _op(1);
        l0.wots[7] = bytes32(uint256(l0.wots[7]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadSubtreeRoot.selector);
        a.execute(target, value, "", l0, false, empty);
    }

    function test_revert_wrongTopLayerSig() public {
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        l1.wots[0] = bytes32(uint256(l1.wots[0]) ^ 1);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
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
        (AegisCCHSBase.LayerSig memory l0, , AegisCCHSBase.LayerSig memory l1) = _op(0);
        vm.expectRevert(AegisCCHSBase.BadTopRoot.selector);
        a.execute(target, value, "", l0, true, l1);
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
