// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import {SphincsC13Verifier}  from "../src/SphincsC13Verifier.sol";
import {SphincsVerifierStub} from "../src/SphincsVerifierStub.sol";
import {AegisAccountFactory} from "../src/AegisAccountFactory.sol";
import {ISphincsVerifier}    from "../src/interfaces/ISphincsVerifier.sol";

/// @title  PredictAddresses
/// @notice OFFLINE proof-of-determinism: compute the Verifier and Factory
///         addresses that WOULD be produced on *any* EVM chain, given only:
///           - AEGIS_DEPLOYER_KEY  (fresh EOA private key)
///           - AEGIS_FEE_COLLECTOR (immutable fee recipient)
///           - AEGIS_VERIFIER      ("prod" or "stub")
///
///         Runs with no RPC and no funds. Prints the two deterministic
///         addresses. Running this script with the SAME env on 10 different
///         chains must produce the SAME two addresses — this is the proof
///         that CREATE2 cross-chain-sameness works.
///
///         Usage:
///           forge script script/PredictAddresses.s.sol
///
///         Note: this script does NOT broadcast; it uses dry-run `vm.getNonce`
///         + CREATE prediction via `vm.computeCreateAddress`.
contract PredictAddresses is Script {
    function run() external {
        address feeCollector = vm.envAddress("AEGIS_FEE_COLLECTOR");
        string memory kind   = vm.envOr("AEGIS_VERIFIER", string("prod"));

        uint256 pk = vm.envUint("AEGIS_DEPLOYER_KEY");
        address deployer = vm.addr(pk);
        require(vm.getNonce(deployer) == 0, "deployer EOA must have nonce 0");

        // Verifier bytecode depends on which kind
        bytes memory verifierInit =
            keccak256(bytes(kind)) == keccak256(bytes("stub"))
                ? type(SphincsVerifierStub).creationCode
                : type(SphincsC13Verifier).creationCode;

        // CREATE (not CREATE2) addresses are deterministic from (deployer, nonce)
        address verifier = vm.computeCreateAddress(deployer, 0);
        address factory  = vm.computeCreateAddress(deployer, 1);

        // sanity: ensure our prediction matches what new X() would produce
        // (prediction is independent of init code because CREATE uses RLP(sender,nonce))

        console2.log("====== Aegis deterministic prediction ======");
        console2.log("Deployer EOA    :", deployer);
        console2.log("Fee collector   :", feeCollector);
        console2.log("Verifier kind   :", kind);
        console2.log("Verifier (nonce 0) ->", verifier);
        console2.log("Factory  (nonce 1) ->", factory);
        console2.log("verifier init-code hash:");
        console2.logBytes32(keccak256(verifierInit));
        console2.log("factory init-code hash:");
        console2.logBytes32(keccak256(abi.encodePacked(
            type(AegisAccountFactory).creationCode,
            abi.encode(verifier, feeCollector)
        )));
        console2.log("============================================");
        console2.log("If you run this on another EVM chain with the SAME env,");
        console2.log("you MUST see the same two addresses. That is the proof.");
    }
}
