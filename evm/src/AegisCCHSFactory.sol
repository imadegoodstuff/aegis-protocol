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
interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
}

contract AegisCCHSFactory {
    event AccountDeployed(address indexed account, bytes32 indexed root, bool sha256Variant);

    /// @notice Accounts created by this factory, keyed by `_salt(root, recRoot, variant)`.
    ///         Idempotence is decided from this record, not from a recomputed
    ///         CREATE2 address, so `deploy` behaves the same on VMs whose
    ///         CREATE2 address prefix differs from `0xff` (TRON uses `0x41`).
    mapping(bytes32 => address) public accountOf;

    error DeployFailed();
    error FundFailed();
    error TokenTransferFailed(address token);

    /// @notice Deploy (or return) the account for `(root, recRoot, variant)`.
    ///         Any ETH sent with the call is forwarded to the account, so
    ///         "create my post-quantum account and move ETH into it" is one
    ///         transaction.
    /// @param sha256Variant  true → `AegisCCHS` (CCHS-S-20), false → `AegisCCHSK` (CCHS-K-20, EVM default)
    function deploy(bytes32 root, bytes32 recRoot, bool sha256Variant)
        public payable returns (address account)
    {
        bytes32 salt = _salt(root, recRoot, sha256Variant);
        account = accountOf[salt];
        if (account == address(0)) {
            if (sha256Variant) {
                account = address(new AegisCCHS{salt: salt}(root, recRoot));
            } else {
                account = address(new AegisCCHSK{salt: salt}(root, recRoot));
            }
            if (account == address(0)) revert DeployFailed();
            accountOf[salt] = account;
            emit AccountDeployed(account, root, sha256Variant);
        }
        if (msg.value != 0) {
            (bool ok,) = account.call{value: msg.value}("");
            if (!ok) revert FundFailed();
        }
    }

    /// @notice `deploy` plus pulling the caller's full balance of each listed
    ///         ERC-20 into the account. Requires prior `approve` to this
    ///         factory for each token. Tokens are moved by `transferFrom`
    ///         from `msg.sender`; the factory never holds funds.
    function deployAndMove(bytes32 root, bytes32 recRoot, bool sha256Variant, address[] calldata erc20s)
        external payable returns (address account)
    {
        account = deploy(root, recRoot, sha256Variant);
        for (uint256 i = 0; i < erc20s.length; i++) {
            IERC20Minimal t = IERC20Minimal(erc20s[i]);
            uint256 bal = t.balanceOf(msg.sender);
            if (bal == 0) continue;
            (bool ok, bytes memory ret) = address(t).call(
                abi.encodeWithSelector(t.transferFrom.selector, msg.sender, account, bal)
            );
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TokenTransferFailed(erc20s[i]);
        }
    }

    /// @notice Counterfactual address for `(root, recRoot, variant)` under the
    ///         EVM CREATE2 rule (`0xff` prefix). On TRON the prefix is `0x41`;
    ///         use `accountOf` after deployment or the client-side predictor.
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
