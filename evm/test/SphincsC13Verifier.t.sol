// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {SphincsC13Verifier} from "../src/SphincsC13Verifier.sol";
import {ISphincsVerifier} from "../src/interfaces/ISphincsVerifier.sol";

/// @notice Smoke tests for the C13 wrapper. End-to-end verification with real
///         SPHINCS+ signatures requires the Python/Rust signer (upstream repo
///         nconsigny/SPHINCS-) and is run there. Here we test the wrapper
///         boundary conditions deterministically.
contract SphincsC13VerifierTest is Test {
    SphincsC13Verifier wrap;

    function setUp() public {
        wrap = new SphincsC13Verifier();
    }

    function test_rejects_bad_pk_length() public view {
        bytes memory shortPk = hex"deadbeef";
        bytes memory sig = new bytes(3688);
        assertFalse(wrap.verify(shortPk, bytes32(0), sig));
    }

    function test_rejects_bad_sig_length() public view {
        bytes memory pk = new bytes(64);
        bytes memory shortSig = hex"00";
        assertFalse(wrap.verify(pk, bytes32(0), shortSig));
    }

    function test_rejects_junk_signature() public view {
        bytes memory pk = new bytes(64);
        // top-align pkRoot (low 128 zero) so the inner verifier doesn't early-revert on canonicality
        for (uint256 i = 32 + 16; i < 64; i++) pk[i] = 0x00;
        bytes memory junk = new bytes(3688);
        assertFalse(wrap.verify(pk, keccak256("hi"), junk));
    }

    function test_inner_address_set_at_construction() public view {
        assertTrue(address(wrap.INNER()) != address(0));
    }
}
