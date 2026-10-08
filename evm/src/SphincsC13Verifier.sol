// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SphincsC13Asm} from "./vendor/SphincsC13Asm.sol";
import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title  SphincsC13Verifier
/// @notice Production SPHINCS+ C13 verifier, wrapping the yul-asm implementation
///         from nconsigny/SPHINCS- (MIT, Nicolas Consigny) under Aegis's
///         chain-agnostic `ISphincsVerifier(pk, digest, sig)` interface.
///
/// @dev    Our `pk` layout is `pkSeed(32) || pkRoot(32)` = 64 bytes.
///         Low 128 bits of pkRoot MUST be zero (FIPS 205 §4.2 top-align).
///         Signature MUST be exactly 3688 bytes.
///         Gas: ~190K per verify on Sepolia (upstream benchmark).
contract SphincsC13Verifier is ISphincsVerifier {
    SphincsC13Asm public immutable INNER;

    constructor() {
        INNER = new SphincsC13Asm();
    }

    /// @inheritdoc ISphincsVerifier
    function verify(
        bytes calldata pk,
        bytes32 digest,
        bytes calldata signature
    ) external view override returns (bool) {
        if (pk.length != 64) return false;
        if (signature.length != 3688) return false;

        bytes32 pkSeed;
        bytes32 pkRoot;
        assembly {
            pkSeed := calldataload(pk.offset)
            pkRoot := calldataload(add(pk.offset, 0x20))
        }
        // SphincsC13Asm.verify reverts on bad sig length (already checked above)
        // and returns true/false for crypto validity.
        try INNER.verify(pkSeed, pkRoot, digest, signature) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}
