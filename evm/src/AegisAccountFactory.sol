// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisAccount} from "./AegisAccount.sol";
import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title  AegisAccountFactory
/// @notice IMMUTABLE CREATE2 factory. Same bytecode + same deployer EOA
///         + same nonce => identical address on every EVM chain.
///
/// @dev    Factory has NO owner, NO upgrade, NO pause. Anyone may deploy
///         an account for any (pqPk, guardian, ecdsaOwner) tuple.
///         Salt is derived from the inputs so each distinct (pqPk, guardian,
///         ecdsaOwner) tuple maps to a unique, predictable account address.
contract AegisAccountFactory {
    ISphincsVerifier public immutable VERIFIER;
    address          public immutable FEE_COLLECTOR;

    event AccountDeployed(
        address indexed account,
        bytes32 indexed pqPkHash,
        address indexed guardian,
        address ecdsaOwner
    );

    error AlreadyDeployed();
    error ZeroAddress();

    constructor(ISphincsVerifier verifier_, address feeCollector_) {
        if (address(verifier_) == address(0)) revert ZeroAddress();
        if (feeCollector_      == address(0)) revert ZeroAddress();
        VERIFIER      = verifier_;
        FEE_COLLECTOR = feeCollector_;
    }

    /// @notice Deploy a new AegisAccount at the deterministic address.
    function deploy(
        bytes calldata pqPk,
        address guardian,
        address ecdsaOwner
    ) external returns (address account) {
        bytes32 salt = _salt(keccak256(pqPk), guardian, ecdsaOwner);
        bytes memory initCode = _initCode(pqPk, guardian, ecdsaOwner);

        address predicted = _predict(salt, keccak256(initCode));
        if (predicted.code.length != 0) revert AlreadyDeployed();

        assembly {
            account := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(account == predicted, "CREATE2 mismatch");

        emit AccountDeployed(account, keccak256(pqPk), guardian, ecdsaOwner);
    }

    /// @notice Predict the AegisAccount address for a given tuple.
    function predictAddress(
        bytes calldata pqPk,
        address guardian,
        address ecdsaOwner
    ) external view returns (address) {
        bytes32 salt = _salt(keccak256(pqPk), guardian, ecdsaOwner);
        bytes memory initCode = _initCode(pqPk, guardian, ecdsaOwner);
        return _predict(salt, keccak256(initCode));
    }

    // ---------------- internals ----------------

    function _salt(bytes32 pqPkHash, address guardian, address ecdsaOwner)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("AEGIS_V1", pqPkHash, guardian, ecdsaOwner));
    }

    function _initCode(
        bytes memory pqPk,
        address guardian,
        address ecdsaOwner
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(AegisAccount).creationCode,
            abi.encode(pqPk, guardian, ecdsaOwner, VERIFIER, FEE_COLLECTOR)
        );
    }

    function _predict(bytes32 salt, bytes32 initCodeHash) internal view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)
        ))));
    }
}
