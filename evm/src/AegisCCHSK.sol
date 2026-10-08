// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AegisCCHSBase} from "./AegisCCHSBase.sol";

/// @title AegisCCHSK — CCHS-K-20: keccak256 parameter set.
/// @notice EVM-native hash (opcode, no precompile call), ~6x cheaper than the
///         SHA-256 set. Not byte-compatible with Bitcoin Script; intended as
///         the default for EVM accounts, which never share signatures with
///         other chains anyway (the chain ID is bound inside every digest).
contract AegisCCHSK is AegisCCHSBase {
    string public constant VERSION = "cchs-k-20/1.0.0";

    constructor(bytes32 _root, bytes32 _recRoot) {
        _init(_root, _recRoot);
    }

    function _hash(bytes memory data) internal pure override returns (bytes32) {
        return keccak256(data);
    }

    function _wotsLeaf(
        uint8 layer,
        uint64 treeIdx,
        uint32 leafIdx,
        bytes32 m,
        bytes32[67] calldata sig
    ) internal pure override returns (bytes32 leaf) {
        uint8[67] memory digits = _digits(m);
        bytes32 base = _adrs(layer, treeIdx, 0x00, leafIdx, 0, 0);
        bytes32 leafAdrs = _adrs(layer, treeIdx, 0x01, leafIdx, 0, 0);

        assembly {
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
                    x := keccak256(0x00, 64)
                }
                mstore(add(buf, add(32, mul(c, 32))), x)
            }

            leaf := keccak256(buf, 2176)
        }
    }

    function _node(bytes32 adrs, bytes32 cur, bytes32 sib, uint256 odd)
        internal pure override returns (bytes32 out)
    {
        assembly {
            let p := mload(0x40)
            mstore(p, adrs)
            switch odd
            case 0 { mstore(add(p, 32), cur) mstore(add(p, 64), sib) }
            default { mstore(add(p, 32), sib) mstore(add(p, 64), cur) }
            out := keccak256(p, 96)
        }
    }
}
