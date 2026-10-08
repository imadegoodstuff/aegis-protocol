// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title AegisAccountV2 — ECDSA-primary smart account with post-quantum insurance.
/// @notice Daily operations use ECDSA (fast, instant, every wallet works).
///         An immutable SPHINCS+ public-key hash is committed at construction.
///         If ECDSA ever becomes forgeable (quantum / AI break), the user can
///         execute `pqRecover()` with a valid SPHINCS+ signature to rotate the
///         ECDSA owner — recovering control of the funds.
///
/// @dev    This design flips the previous V1 architecture (PQ primary, ECDSA
///         fallback). The new design is deployable to mainnet TODAY because:
///
///         1. Daily `execute()` uses `ecrecover` (EVM native, cheap, fast)
///         2. PQ verifier is only invoked on `pqRecover()` which is RARE
///         3. The expensive on-chain SPHINCS+ verification happens only when
///            the user actually needs quantum insurance, not every tx.
///         4. Users get normal UX (MetaMask one-click) with real PQ insurance.
///
///         Everything is immutable per-user. No proxy, no admin, no upgrade.
contract AegisAccountV2 {
    // ---- immutable state ----
    string  public constant VERSION         = "0.2.0";
    uint256 public constant MAX_FEE_BPS     = 2000;    // 20% ceiling
    uint256 public constant PROTOCOL_FEE_BPS = 1000;   // 10% of gas

    /// @notice Current ECDSA owner. Can rotate via PQ recovery.
    address public ecdsaOwner;

    /// @notice Immutable commitment to the user's SPHINCS+ public key.
    ///         `keccak256(pq_pk)` where `pq_pk` is the user's FIPS 205
    ///         SLH-DSA-SHAKE-192s public key (48 bytes).
    bytes32 public immutable PQ_PK_HASH;

    /// @notice Immutable SPHINCS+ verifier contract (shared across accounts).
    ISphincsVerifier public immutable VERIFIER;

    /// @notice Immutable fee recipient. 20% hard ceiling in MAX_FEE_BPS.
    address public immutable FEE_COLLECTOR;

    // ---- mutable state ----
    uint256 public nonce;
    uint256 public pqRecoveryNonce;  // separate nonce for recovery, prevents replay

    // ---- events ----
    event Executed(uint256 indexed nonce, address indexed target, uint256 value);
    event BatchExecuted(uint256 indexed nonce, uint256 count);
    event FeePaid(address indexed collector, uint256 amount);
    event PqRecovered(address indexed oldOwner, address indexed newOwner, uint256 recoveryNonce);

    // ---- errors ----
    error NotOwner();
    error BadNonce(uint256 expected, uint256 got);
    error CallFailed(uint256 index);
    error LengthMismatch();
    error ZeroAddress();
    error InvalidPqSignature();
    error InvalidPqPublicKey();

    // ---- construction ----
    constructor(
        address _ecdsaOwner,
        bytes32 _pqPkHash,
        ISphincsVerifier _verifier,
        address _feeCollector
    ) {
        if (_ecdsaOwner == address(0))     revert ZeroAddress();
        if (_pqPkHash == bytes32(0))       revert InvalidPqPublicKey();
        if (address(_verifier) == address(0)) revert ZeroAddress();
        if (_feeCollector == address(0))   revert ZeroAddress();
        ecdsaOwner    = _ecdsaOwner;
        PQ_PK_HASH    = _pqPkHash;
        VERIFIER      = _verifier;
        FEE_COLLECTOR = _feeCollector;
    }

    receive() external payable {}

    // ---- daily path (ECDSA, free & fast) ----

    /// @notice Execute a call. Caller must be `ecdsaOwner`.
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory result) {
        uint256 startGas = gasleft();
        if (msg.sender != ecdsaOwner) revert NotOwner();
        unchecked { nonce += 1; }

        bool ok;
        (ok, result) = target.call{value: value}(data);
        if (!ok) revert CallFailed(0);

        _collectFee(startGas);
        emit Executed(nonce, target, value);
    }

    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[]   calldata datas
    ) external payable {
        uint256 startGas = gasleft();
        if (msg.sender != ecdsaOwner) revert NotOwner();
        if (targets.length != values.length || values.length != datas.length) {
            revert LengthMismatch();
        }
        unchecked { nonce += 1; }

        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok, ) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) revert CallFailed(i);
        }

        _collectFee(startGas);
        emit BatchExecuted(nonce, targets.length);
    }

    // ---- emergency: PQ recovery ----

    /// @notice Rotate ecdsaOwner to a new address, authorised by a SPHINCS+
    ///         signature from the key committed at construction. Use this
    ///         when ECDSA is forgeable (quantum / AI break).
    ///
    /// @param  newOwner   new ECDSA owner
    /// @param  pqPk       raw SPHINCS+ public key (must hash to PQ_PK_HASH)
    /// @param  pqSig      SPHINCS+ signature over `_recoveryDigest(newOwner)`
    function pqRecover(
        address newOwner,
        bytes calldata pqPk,
        bytes calldata pqSig
    ) external {
        if (newOwner == address(0))                revert ZeroAddress();
        if (keccak256(pqPk) != PQ_PK_HASH)         revert InvalidPqPublicKey();

        bytes32 digest = _recoveryDigest(newOwner);
        if (!VERIFIER.verify(pqPk, digest, pqSig)) revert InvalidPqSignature();

        address old = ecdsaOwner;
        ecdsaOwner = newOwner;
        unchecked { pqRecoveryNonce += 1; }
        emit PqRecovered(old, newOwner, pqRecoveryNonce);
    }

    /// @notice Digest that `pqSig` in `pqRecover` must cover.
    function recoveryDigest(address newOwner) external view returns (bytes32) {
        return _recoveryDigest(newOwner);
    }

    function _recoveryDigest(address newOwner) internal view returns (bytes32) {
        return keccak256(
            abi.encode("AEGIS_PQ_RECOVER_V2", block.chainid, address(this), newOwner, pqRecoveryNonce)
        );
    }

    // ---- internals ----

    function _collectFee(uint256 startGas) internal {
        uint256 gasUsed = startGas - gasleft();
        uint256 fee = (gasUsed * tx.gasprice * PROTOCOL_FEE_BPS) / 10_000;
        if (fee == 0 || address(this).balance < fee) return;
        (bool ok,) = FEE_COLLECTOR.call{value: fee}("");
        if (ok) emit FeePaid(FEE_COLLECTOR, fee);
    }
}
