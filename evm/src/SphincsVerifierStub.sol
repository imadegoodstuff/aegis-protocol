// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title SphincsVerifierStub
/// @notice **STUB — DO NOT DEPLOY TO MAINNET.**
///         This is a placeholder that implements a trivial verification rule
///         so the rest of the system (AegisAccount, Factory, tests) can be
///         compiled and exercised end-to-end before the real SPHINCS+ verifier
///         is wired in.
///
///         In production, replace this contract with a fork of
///         nconsigny/SPHINCs- C13 verifier (FIPS 205 §11.2.2, 32-byte ADRS,
///         standalone verify gas ~190K on Sepolia).
///
///         The stub's verification rule is:
///         ``sha256(pk || digest) == bytes32(signature[0..32])``
///         which lets us drive the full account flow in tests without
///         needing a real 16KB SPHINCS+ signature.
contract SphincsVerifierStub is ISphincsVerifier {
    /// @dev **STUB** — real impl must do FIPS 205 verification.
    function verify(
        bytes calldata pk,
        bytes32 digest,
        bytes calldata signature
    ) external pure override returns (bool) {
        if (signature.length < 32) return false;
        bytes32 expected = sha256(abi.encodePacked(pk, digest));
        bytes32 provided;
        // read first 32 bytes of signature
        assembly {
            provided := calldataload(signature.offset)
        }
        return expected == provided;
    }
}
