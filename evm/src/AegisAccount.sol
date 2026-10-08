// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title  AegisAccount
/// @author Aegis Protocol
/// @notice Per-user, IMMUTABLE post-quantum smart account.
///         Daily path:  SPHINCS+-192s signature (hash-only, PQ-safe)
///         Fallback:    ECDSA → 7-day timelock → GUARDIAN address only
///
/// @dev    Contract has NO proxy, NO selfdestruct, NO upgradeTo, NO owner,
///         NO pause, NO admin setter. Everything meaningful is `immutable`
///         or `constant`. Deployer has no privileges after construction.
///
///         The ONLY addresses that can ever receive funds from this account are:
///           - any address, via `execute*` paths authorized by a valid PQ sig
///           - the GUARDIAN, via the ECDSA fallback after a 7-day delay
///
///         `cancelEmergencyExit` lets the PQ key unilaterally veto any pending
///         ECDSA exit. This is the defense against an attacker who has recovered
///         the user's ECDSA private key (e.g. via a future quantum / AI attack).
contract AegisAccount {
    // ---------------------------------------------------------------- //
    //                     IMMUTABLE / CONSTANT STATE                   //
    // ---------------------------------------------------------------- //

    string  public constant VERSION           = "0.1.0";
    uint256 public constant MAX_FEE_BPS       = 2000;        // hard ceiling: 20%
    uint256 public constant PROTOCOL_FEE_BPS  = 1000;        // charged: 10% of gas
    uint256 public constant TIMELOCK          = 7 days;

    bytes32  public immutable PQ_PK_HASH;      // keccak256(SPHINCS+ public key)
    address  public immutable GUARDIAN;         // ECDSA fallback destination
    address  public immutable ECDSA_OWNER;      // EOA allowed to initiate exit
    ISphincsVerifier public immutable VERIFIER;
    address  public immutable FEE_COLLECTOR;

    // ---------------------------------------------------------------- //
    //                           MUTABLE STATE                          //
    // ---------------------------------------------------------------- //

    uint256 public nonce;                       // monotonic replay guard
    uint256 public exitTimestamp;               // 0 = no pending exit
    uint256 public exitNonce;                   // nonce for ECDSA exit sig

    // ---------------------------------------------------------------- //
    //                              EVENTS                              //
    // ---------------------------------------------------------------- //

    event Executed(uint256 indexed nonce, address indexed target, uint256 value, uint256 feePaid);
    event BatchExecuted(uint256 indexed nonce, uint256 count, uint256 feePaid);
    event EmergencyExitInitiated(uint256 unlockAt, uint256 exitNonce);
    event EmergencyExitCancelled(uint256 exitNonce);
    event EmergencyExitFinalized(address indexed guardian, uint256 ethAmount, uint256 tokenCount);
    event ProtocolFeePaid(address indexed collector, uint256 amount);

    // ---------------------------------------------------------------- //
    //                              ERRORS                              //
    // ---------------------------------------------------------------- //

    error InvalidPqSignature();
    error InvalidEcdsaSignature();
    error BadNonce(uint256 expected, uint256 provided);
    error LengthMismatch();
    error CallFailed(uint256 index);
    error NothingToFinalize();
    error TimelockNotElapsed(uint256 remaining);
    error ZeroAddress();
    error FeeTransferFailed();

    // ---------------------------------------------------------------- //
    //                           CONSTRUCTOR                            //
    // ---------------------------------------------------------------- //

    /// @param pqPk           Full SPHINCS+ public key bytes (stored only as hash)
    /// @param guardian_      Immutable recipient of any ECDSA-fallback exit
    /// @param ecdsaOwner_    EOA permitted to initiate the exit timer
    /// @param verifier_      SPHINCS+ verifier contract (shared across all accounts)
    /// @param feeCollector_  Immutable address receiving protocol fees
    constructor(
        bytes memory pqPk,
        address guardian_,
        address ecdsaOwner_,
        ISphincsVerifier verifier_,
        address feeCollector_
    ) {
        if (guardian_      == address(0)) revert ZeroAddress();
        if (ecdsaOwner_    == address(0)) revert ZeroAddress();
        if (address(verifier_)   == address(0)) revert ZeroAddress();
        if (feeCollector_  == address(0)) revert ZeroAddress();
        if (pqPk.length == 0)             revert ZeroAddress();

        PQ_PK_HASH    = keccak256(pqPk);
        GUARDIAN      = guardian_;
        ECDSA_OWNER   = ecdsaOwner_;
        VERIFIER      = verifier_;
        FEE_COLLECTOR = feeCollector_;
    }

    receive() external payable {}

    // ---------------------------------------------------------------- //
    //                       DAILY PATH (PQ sig)                        //
    // ---------------------------------------------------------------- //

    /// @notice Execute a single call authorized by a SPHINCS+ signature.
    /// @dev    Caller provides the raw `pqPk` so verifier can hash & verify.
    ///         Account stores only the hash to save storage/calldata.
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 providedNonce,
        bytes calldata pqPk,
        bytes calldata pqSig
    ) external payable returns (bytes memory result) {
        uint256 startGas = gasleft();
        _authorizePq(
            keccak256(
                abi.encode(block.chainid, address(this), providedNonce, target, value, data)
            ),
            providedNonce,
            pqPk,
            pqSig
        );

        bool ok;
        (ok, result) = target.call{value: value}(data);
        if (!ok) revert CallFailed(0);

        uint256 fee = _collectFee(startGas);
        emit Executed(providedNonce, target, value, fee);
    }

    /// @notice Execute an array of calls atomically authorized by one PQ sig.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[]   calldata datas,
        uint256 providedNonce,
        bytes calldata pqPk,
        bytes calldata pqSig
    ) external payable {
        uint256 startGas = gasleft();
        if (targets.length != values.length || values.length != datas.length) {
            revert LengthMismatch();
        }

        _authorizePq(
            keccak256(
                abi.encode(block.chainid, address(this), providedNonce, targets, values, datas)
            ),
            providedNonce,
            pqPk,
            pqSig
        );

        for (uint256 i = 0; i < targets.length; ++i) {
            (bool ok, ) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) revert CallFailed(i);
        }

        uint256 fee = _collectFee(startGas);
        emit BatchExecuted(providedNonce, targets.length, fee);
    }

    // ---------------------------------------------------------------- //
    //                       EMERGENCY (ECDSA) PATH                     //
    // ---------------------------------------------------------------- //

    /// @notice Start the 7-day timelock towards sending all assets to GUARDIAN.
    /// @dev    Signed by ECDSA_OWNER (EOA key). Can be cancelled by PQ key.
    function initiateEmergencyExit(bytes calldata ecdsaSig) external {
        bytes32 digest = _exitDigest(exitNonce);
        if (_recoverEcdsa(digest, ecdsaSig) != ECDSA_OWNER) revert InvalidEcdsaSignature();
        exitTimestamp = block.timestamp + TIMELOCK;
        emit EmergencyExitInitiated(exitTimestamp, exitNonce);
    }

    /// @notice Cancel a pending exit via a PQ signature.
    /// @dev    Protects users when an attacker has stolen their ECDSA key
    ///         (e.g. via quantum attack). PQ key survives.
    function cancelEmergencyExit(bytes calldata pqPk, bytes calldata pqSig) external {
        bytes32 digest = keccak256(
            abi.encode("AEGIS_CANCEL_EXIT", block.chainid, address(this), exitNonce)
        );
        if (keccak256(pqPk) != PQ_PK_HASH) revert InvalidPqSignature();
        if (!VERIFIER.verify(pqPk, digest, pqSig)) revert InvalidPqSignature();

        emit EmergencyExitCancelled(exitNonce);
        exitTimestamp = 0;
        unchecked { exitNonce += 1; } // invalidates the ECDSA sig that started it
    }

    /// @notice After timelock elapses, sweep ETH + listed tokens to GUARDIAN.
    /// @dev    Permissionless to call. No fee charged on fallback path.
    function finalizeEmergencyExit(address[] calldata erc20Tokens) external {
        if (exitTimestamp == 0) revert NothingToFinalize();
        if (block.timestamp < exitTimestamp) {
            revert TimelockNotElapsed(exitTimestamp - block.timestamp);
        }

        uint256 ethBal = address(this).balance;
        uint256 moved;

        for (uint256 i = 0; i < erc20Tokens.length; ++i) {
            address t = erc20Tokens[i];
            if (t == address(0)) continue;
            // read balance via staticcall
            (bool okR, bytes memory br) = t.staticcall(
                abi.encodeWithSelector(0x70a08231, address(this))
            );
            if (!okR || br.length < 32) continue;
            uint256 bal = abi.decode(br, (uint256));
            if (bal == 0) continue;
            // transfer(GUARDIAN, bal)
            (bool okT, bytes memory bt) = t.call(
                abi.encodeWithSelector(0xa9059cbb, GUARDIAN, bal)
            );
            if (!okT) continue;
            if (bt.length > 0 && !abi.decode(bt, (bool))) continue;
            unchecked { moved += 1; }
        }

        if (ethBal > 0) {
            (bool ok,) = GUARDIAN.call{value: ethBal}("");
            if (!ok) revert CallFailed(0);
        }

        exitTimestamp = 0;
        unchecked {
            exitNonce += 1;
            nonce     += 1;    // bump nonce too to invalidate any pending PQ ops
        }
        emit EmergencyExitFinalized(GUARDIAN, ethBal, moved);
    }

    // ---------------------------------------------------------------- //
    //                              HELPERS                             //
    // ---------------------------------------------------------------- //

    function predictedDigest(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 providedNonce
    ) external view returns (bytes32) {
        return keccak256(
            abi.encode(block.chainid, address(this), providedNonce, target, value, data)
        );
    }

    // ---------------------------------------------------------------- //
    //                             INTERNALS                            //
    // ---------------------------------------------------------------- //

    function _authorizePq(
        bytes32 digest,
        uint256 providedNonce,
        bytes calldata pqPk,
        bytes calldata pqSig
    ) internal {
        if (providedNonce != nonce + 1) revert BadNonce(nonce + 1, providedNonce);
        if (keccak256(pqPk) != PQ_PK_HASH) revert InvalidPqSignature();
        if (!VERIFIER.verify(pqPk, digest, pqSig)) revert InvalidPqSignature();
        unchecked { nonce = providedNonce; }
    }

    function _collectFee(uint256 startGas) internal returns (uint256 feeWei) {
        uint256 gasUsed = startGas - gasleft();
        feeWei = (gasUsed * tx.gasprice * PROTOCOL_FEE_BPS) / 10_000;
        if (feeWei == 0) return 0;
        if (address(this).balance < feeWei) {
            // Not enough to pay fee; don't revert the user's tx, just skip fee.
            // (Alternative: revert. Chosen policy: user's op succeeds regardless.)
            return 0;
        }
        (bool ok,) = FEE_COLLECTOR.call{value: feeWei}("");
        if (!ok) revert FeeTransferFailed();
        emit ProtocolFeePaid(FEE_COLLECTOR, feeWei);
    }

    function _exitDigest(uint256 n) internal view returns (bytes32) {
        return keccak256(
            abi.encode("AEGIS_INIT_EXIT", block.chainid, address(this), n)
        );
    }

    /// @dev Minimal ECDSA recover using ecrecover precompile.
    function _recoverEcdsa(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        // EIP-2 low-s
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        bytes32 ethDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        return ecrecover(ethDigest, v, r, s);
    }
}
