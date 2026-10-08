// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title ISphincsVerifier
/// @notice Minimal interface for a SPHINCS+-192s / SLH-DSA (FIPS 205) verifier.
/// @dev    Implementations MUST be stateless and side-effect-free (view).
///         Reference implementation to fork: nconsigny/SPHINCs- C13 verifier.
interface ISphincsVerifier {
    /// @notice Verify a SPHINCS+-192s signature over `digest`.
    /// @param pk        48-byte public key: PK.seed (32) || PK.root (16-32 depending on variant)
    /// @param digest    32-byte message digest (keccak256 of canonical account payload)
    /// @param signature SPHINCS+ signature bytes (~16KB for -192s standard params)
    /// @return ok       true iff signature verifies under pk for digest
    function verify(
        bytes calldata pk,
        bytes32 digest,
        bytes calldata signature
    ) external view returns (bool ok);
}
