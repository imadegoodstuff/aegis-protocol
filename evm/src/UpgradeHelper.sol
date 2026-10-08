// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisAccountV2Factory} from "./AegisAccountV2Factory.sol";

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @title UpgradeHelper — one-click "deploy my Aegis account + move all my assets in".
/// @notice User flow (frontend):
///         1. User signs standard ERC-20 `approve(UpgradeHelper, max)` on each token
///            (or uses Permit2 for a single sig). The approvals go to this helper.
///         2. User calls `upgrade(pqPkHash, erc20s, msg.value)` once.
///         3. We deploy the user's AegisAccountV2 (CREATE2), then pull every approved
///            ERC-20 and the attached ETH into it. Atomic.
///
/// @dev    This helper is stateless and immutable. It does not hold funds.
contract UpgradeHelper {
    AegisAccountV2Factory public immutable FACTORY;

    event Upgraded(address indexed user, address indexed account, uint256 ethMoved, uint256 tokensMoved);

    error FactoryZero();
    error TokenPullFailed(address token);
    error EthForwardFailed();

    constructor(AegisAccountV2Factory factory_) {
        if (address(factory_) == address(0)) revert FactoryZero();
        FACTORY = factory_;
    }

    /// @notice One-shot upgrade. Caller approves this helper for each token first.
    /// @param pqPkHash  keccak256(user's SPHINCS+ pubkey)
    /// @param erc20s    tokens to pull from msg.sender (one approve each)
    function upgrade(
        bytes32 pqPkHash,
        address[] calldata erc20s
    ) external payable returns (address acc) {
        // 1. deploy (or fetch) the user's Aegis account
        acc = FACTORY.predictAddress(msg.sender, pqPkHash);
        if (acc.code.length == 0) {
            acc = FACTORY.deploy(msg.sender, pqPkHash);
        }

        // 2. forward ETH
        if (msg.value > 0) {
            (bool ok, ) = acc.call{value: msg.value}("");
            if (!ok) revert EthForwardFailed();
        }

        // 3. pull every approved ERC-20
        uint256 moved = 0;
        for (uint256 i = 0; i < erc20s.length; ++i) {
            IERC20 t = IERC20(erc20s[i]);
            uint256 bal = t.balanceOf(msg.sender);
            if (bal == 0) continue;
            bool ok = t.transferFrom(msg.sender, acc, bal);
            if (!ok) revert TokenPullFailed(erc20s[i]);
            unchecked { moved += 1; }
        }

        emit Upgraded(msg.sender, acc, msg.value, moved);
    }

    function predict(address user, bytes32 pqPkHash) external view returns (address) {
        return FACTORY.predictAddress(user, pqPkHash);
    }
}
