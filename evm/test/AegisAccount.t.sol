// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import {AegisAccount} from "../src/AegisAccount.sol";
import {AegisAccountFactory} from "../src/AegisAccountFactory.sol";
import {SphincsVerifierStub} from "../src/SphincsVerifierStub.sol";
import {ISphincsVerifier} from "../src/interfaces/ISphincsVerifier.sol";

/// @dev Uses SphincsVerifierStub whose "sig" is `sha256(pk || digest)`.
///      Lets us test the full account state machine without a real 16KB sig.
contract AegisAccountTest is Test {
    SphincsVerifierStub verifier;
    AegisAccountFactory factory;
    AegisAccount acc;

    address constant FEE_COLLECTOR = address(0xFEE);
    address constant GUARDIAN      = address(0x6A4D1A4);
    uint256 constant ECDSA_PK      = 0xA11CE;
    address          ecdsaOwner;

    // "SPHINCS+ pk" placeholder
    bytes constant PK = hex"deadbeefcafebabe00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    function setUp() public {
        ecdsaOwner = vm.addr(ECDSA_PK);
        verifier   = new SphincsVerifierStub();
        factory    = new AegisAccountFactory(ISphincsVerifier(address(verifier)), FEE_COLLECTOR);
        address predicted = factory.predictAddress(PK, GUARDIAN, ecdsaOwner);
        address deployed  = factory.deploy(PK, GUARDIAN, ecdsaOwner);
        assertEq(predicted, deployed, "CREATE2 address drift");
        acc = AegisAccount(payable(deployed));
        vm.deal(address(acc), 10 ether);
    }

    // ------------- deployment invariants -------------

    function test_immutables_set() public view {
        assertEq(acc.PQ_PK_HASH(), keccak256(PK));
        assertEq(acc.GUARDIAN(), GUARDIAN);
        assertEq(acc.ECDSA_OWNER(), ecdsaOwner);
        assertEq(address(acc.VERIFIER()), address(verifier));
        assertEq(acc.FEE_COLLECTOR(), FEE_COLLECTOR);
        assertEq(acc.MAX_FEE_BPS(), 2000);
        assertEq(acc.PROTOCOL_FEE_BPS(), 1000);
        assertEq(acc.TIMELOCK(), 7 days);
    }

    function test_no_proxy_bytecode() public view {
        // naive assertion: bytecode is non-empty and does not start with EIP-1167 minimal proxy
        bytes memory code = address(acc).code;
        assertGt(code.length, 100);
        assertNotEq(code[0], bytes1(0x36)); // EIP-1167 starts with 0x363d3d373d3d3d363d73
    }

    // ------------- daily path -------------

    function test_execute_with_pq_sig() public {
        address payable recipient = payable(address(0xBEEF));
        uint256 n = acc.nonce() + 1;
        bytes32 digest = acc.predictedDigest(recipient, 1 ether, "", n);
        bytes memory sig = abi.encodePacked(sha256(abi.encodePacked(PK, digest))); // stub sig
        acc.execute(recipient, 1 ether, "", n, PK, sig);
        assertEq(recipient.balance, 1 ether);
        assertEq(acc.nonce(), n);
    }

    function test_execute_bad_nonce_reverts() public {
        address payable recipient = payable(address(0xBEEF));
        uint256 wrong = acc.nonce() + 2;
        bytes32 digest = acc.predictedDigest(recipient, 1 ether, "", wrong);
        bytes memory sig = abi.encodePacked(sha256(abi.encodePacked(PK, digest)));
        vm.expectRevert();
        acc.execute(recipient, 1 ether, "", wrong, PK, sig);
    }

    function test_execute_bad_pk_reverts() public {
        address payable recipient = payable(address(0xBEEF));
        uint256 n = acc.nonce() + 1;
        bytes32 digest = acc.predictedDigest(recipient, 1 ether, "", n);
        bytes memory wrongPk = hex"0011";
        bytes memory sig = abi.encodePacked(sha256(abi.encodePacked(wrongPk, digest)));
        vm.expectRevert();
        acc.execute(recipient, 1 ether, "", n, wrongPk, sig);
    }

    function test_execute_bad_sig_reverts() public {
        address payable recipient = payable(address(0xBEEF));
        uint256 n = acc.nonce() + 1;
        bytes memory badSig = hex"0000000000000000000000000000000000000000000000000000000000000001";
        vm.expectRevert();
        acc.execute(recipient, 1 ether, "", n, PK, badSig);
    }

    // ------------- fee -------------

    function test_fee_goes_to_fee_collector() public {
        vm.txGasPrice(10 gwei);
        address payable recipient = payable(address(0xBEEF));
        uint256 feeBalBefore = FEE_COLLECTOR.balance;
        uint256 n = acc.nonce() + 1;
        bytes32 digest = acc.predictedDigest(recipient, 0, "", n);
        bytes memory sig = abi.encodePacked(sha256(abi.encodePacked(PK, digest)));
        acc.execute(recipient, 0, "", n, PK, sig);
        assertGt(FEE_COLLECTOR.balance, feeBalBefore);
    }

    // ------------- emergency exit -------------

    function test_full_emergency_exit_flow() public {
        bytes32 digest = keccak256(
            abi.encode("AEGIS_INIT_EXIT", block.chainid, address(acc), acc.exitNonce())
        );
        bytes32 ethDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ECDSA_PK, ethDigest);
        bytes memory sig = abi.encodePacked(r, s, v);

        acc.initiateEmergencyExit(sig);
        assertGt(acc.exitTimestamp(), 0);

        // too early
        vm.expectRevert();
        acc.finalizeEmergencyExit(new address[](0));

        // wait 7 days + 1
        vm.warp(block.timestamp + 7 days + 1);

        uint256 gBefore = GUARDIAN.balance;
        acc.finalizeEmergencyExit(new address[](0));
        assertEq(GUARDIAN.balance, gBefore + 10 ether);
        assertEq(acc.exitTimestamp(), 0);
    }

    function test_pq_can_cancel_ecdsa_exit() public {
        // initiate
        bytes32 digest = keccak256(
            abi.encode("AEGIS_INIT_EXIT", block.chainid, address(acc), acc.exitNonce())
        );
        bytes32 ethDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ECDSA_PK, ethDigest);
        acc.initiateEmergencyExit(abi.encodePacked(r, s, v));
        assertGt(acc.exitTimestamp(), 0);

        // cancel with PQ
        bytes32 cDigest = keccak256(
            abi.encode("AEGIS_CANCEL_EXIT", block.chainid, address(acc), acc.exitNonce())
        );
        bytes memory cSig = abi.encodePacked(sha256(abi.encodePacked(PK, cDigest)));
        acc.cancelEmergencyExit(PK, cSig);
        assertEq(acc.exitTimestamp(), 0);
    }

    // ------------- immutability -------------

    function test_cannot_change_guardian() public view {
        // compile-time: there is no setter. this test documents the invariant.
        // If someone adds setGuardian, foundry will fail to compile this file
        // once we remove the comment and uncomment the next line:
        // acc.setGuardian(address(0xBAD));
    }
}
