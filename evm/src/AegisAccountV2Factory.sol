// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisAccountV2}  from "./AegisAccountV2.sol";
import {ISphincsVerifier} from "./interfaces/ISphincsVerifier.sol";

/// @title AegisAccountV2Factory — CREATE2 factory, same address on every EVM chain.
contract AegisAccountV2Factory {
    ISphincsVerifier public immutable VERIFIER;
    address          public immutable FEE_COLLECTOR;

    event AccountDeployed(address indexed account, address indexed owner, bytes32 pqPkHash);

    error AlreadyDeployed();
    error ZeroAddress();

    constructor(ISphincsVerifier verifier_, address feeCollector_) {
        if (address(verifier_) == address(0)) revert ZeroAddress();
        if (feeCollector_      == address(0)) revert ZeroAddress();
        VERIFIER      = verifier_;
        FEE_COLLECTOR = feeCollector_;
    }

    /// @notice Deploy an account for `owner` committing `pqPkHash`.
    function deploy(address owner, bytes32 pqPkHash) external returns (address acc) {
        bytes32 salt = _salt(owner, pqPkHash);
        bytes memory init = _initCode(owner, pqPkHash);
        address predicted = _predict(salt, keccak256(init));
        if (predicted.code.length != 0) revert AlreadyDeployed();

        assembly { acc := create2(0, add(init, 0x20), mload(init), salt) }
        require(acc == predicted, "CREATE2 mismatch");

        emit AccountDeployed(acc, owner, pqPkHash);
    }

    function predictAddress(address owner, bytes32 pqPkHash) external view returns (address) {
        bytes32 salt = _salt(owner, pqPkHash);
        return _predict(salt, keccak256(_initCode(owner, pqPkHash)));
    }

    function _salt(address owner, bytes32 pqPkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("AEGIS_V2", owner, pqPkHash));
    }

    function _initCode(address owner, bytes32 pqPkHash) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(AegisAccountV2).creationCode,
            abi.encode(owner, pqPkHash, VERIFIER, FEE_COLLECTOR)
        );
    }

    function _predict(bytes32 salt, bytes32 initCodeHash) internal view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)
        ))));
    }
}
