// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisCCHS}  from "./AegisCCHS.sol";
import {AegisCCHSK} from "./AegisCCHSK.sol";

/// @title AegisCCHSFactory — CREATE2 deployer for CCHS accounts.
/// @notice Deployed at the same address on every EVM chain (same deployer,
///         same nonce, metadata-free bytecode), so a given (root, recRoot)
///         yields the same account address everywhere. Anyone may deploy an
///         account for anyone; deployment is permissionless and idempotent.
///
///         No owner. No upgrade. No fee.
contract AegisCCHSFactory {
    event AccountDeployed(address indexed account, bytes32 indexed root, bool sha256Variant);

    error DeployFailed();

    /// @notice Deploy (or return) the account for `(root, recRoot, variant)`.
    /// @param sha256Variant  true → `AegisCCHS` (CCHS-S-20), false → `AegisCCHSK` (CCHS-K-20, EVM default)
    function deploy(bytes32 root, bytes32 recRoot, bool sha256Variant)
        external returns (address account)
    {
        account = predict(root, recRoot, sha256Variant);
        if (account.code.length != 0) return account;

        bytes32 salt = _salt(root, recRoot, sha256Variant);
        if (sha256Variant) {
            account = address(new AegisCCHS{salt: salt}(root, recRoot));
        } else {
            account = address(new AegisCCHSK{salt: salt}(root, recRoot));
        }
        if (account == address(0)) revert DeployFailed();
        emit AccountDeployed(account, root, sha256Variant);
    }

    /// @notice Counterfactual address for `(root, recRoot, variant)`.
    function predict(bytes32 root, bytes32 recRoot, bool sha256Variant)
        public view returns (address)
    {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                sha256Variant ? type(AegisCCHS).creationCode : type(AegisCCHSK).creationCode,
                abi.encode(root, recRoot)
            )
        );
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), _salt(root, recRoot, sha256Variant), initCodeHash
        )))));
    }

    function _salt(bytes32 root, bytes32 recRoot, bool sha256Variant) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(root, recRoot, sha256Variant));
    }
}
