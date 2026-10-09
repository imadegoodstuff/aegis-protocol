// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisCCHSBase} from "./AegisCCHSBase.sol";

/// @title AegisCCHS — CCHS-S-20: SHA-256 parameter set.
/// @notice Byte-compatible with every non-EVM implementation (Solana, Cosmos,
///         Move, NEAR, TON, Cairo, Bitcoin Script). Hot loops call the SHA-256
///         precompile (0x02) directly from assembly.
contract AegisCCHS is AegisCCHSBase {
    string public constant VERSION = "cchs-s-20/1.0.0";

    constructor(bytes32 _root, bytes32 _recRoot, bytes16 _seed) {
        _init(_root, _recRoot, _seed);
    }

    function _hash(bytes memory data) internal pure override returns (bytes32) {
        return sha256(data);
    }

    function _wotsLeaf(
        uint256 seed,
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal view override returns (bytes32 leaf) {
        uint8[67] memory digits = _digits(m);
        bytes32 base = _adrs(seed, layer, treeIdx, 0x00, leafIdx, 0, 0);
        bytes32 leafAdrs = _adrs(seed, layer, treeIdx, 0x01, leafIdx, 0, 0);

        assembly {
            // buf: [leafAdrs][pk_0]...[pk_66] = 32 + 67*32 bytes
            let buf := mload(0x40)
            mstore(0x40, add(buf, 2176))
            mstore(buf, leafAdrs)

            for { let c := 0 } lt(c, 67) { c := add(c, 1) } {
                let x := calldataload(add(sig, mul(c, 32)))
                let adrsC := or(base, shl(136, c))
                let start := mload(add(digits, mul(c, 32)))
                for { let s := start } lt(s, 15) { s := add(s, 1) } {
                    mstore(0x00, or(adrsC, shl(128, s)))
                    mstore(0x20, x)
                    if iszero(staticcall(gas(), 0x02, 0x00, 64, 0x00, 32)) { revert(0, 0) }
                    x := mload(0x00)
                }
                mstore(add(buf, add(32, mul(c, 32))), x)
            }

            if iszero(staticcall(gas(), 0x02, buf, 2176, 0x00, 32)) { revert(0, 0) }
            leaf := mload(0x00)
        }
    }

    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal view override returns (bytes32 out)
    {
        assembly {
            let p := mload(0x40)
            mstore(p, adrs)
            switch odd
            case 0 { mstore(add(p, 32), cur) mstore(add(p, 64), sib) }
            default { mstore(add(p, 32), sib) mstore(add(p, 64), cur) }
            if iszero(staticcall(gas(), 0x02, p, 96, 0x00, 32)) { revert(0, 0) }
            out := mload(0x00)
        }
    }
}
