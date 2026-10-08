// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import {SphincsVerifierStub} from "../src/SphincsVerifierStub.sol";
import {AegisAccountFactory} from "../src/AegisAccountFactory.sol";
import {ISphincsVerifier} from "../src/interfaces/ISphincsVerifier.sol";

/// @notice Deploys Verifier (nonce 0) and Factory (nonce 1) from a dedicated
///         deployer EOA so that the two addresses are identical across every
///         EVM chain.
///
///         Usage (per chain):
///             forge script script/DeployMultichain.s.sol \
///                 --rpc-url <chain> --broadcast --slow \
///                 --private-key $AEGIS_DEPLOYER_KEY
///
///         The deployer EOA MUST be freshly created and MUST have nonce 0 on
///         every target chain. After deploying to all N chains, the deployer
///         key MUST be publicly destroyed. See docs/BURN_CEREMONY.md.
///
///         FEE_COLLECTOR is set via env; make it an immutable timelock /
///         burn address of your choice (same across chains for consistency).
contract DeployMultichain is Script {
    function run() external returns (address verifier, address factory) {
        address feeCollector = vm.envAddress("AEGIS_FEE_COLLECTOR");
        require(feeCollector != address(0), "FEE_COLLECTOR=0");

        uint256 pk = vm.envUint("AEGIS_DEPLOYER_KEY");
        vm.startBroadcast(pk);

        // nonce 0 -> SphincsVerifier (stub for v0.1; replace with C13 fork in prod)
        verifier = address(new SphincsVerifierStub());

        // nonce 1 -> Factory
        factory = address(new AegisAccountFactory(ISphincsVerifier(verifier), feeCollector));

        vm.stopBroadcast();

        console2.log("Chain id        :", block.chainid);
        console2.log("Verifier        :", verifier);
        console2.log("Factory         :", factory);
        console2.log("Fee collector   :", feeCollector);
        console2.log("---");
        console2.log("IMPORTANT: After deploying to ALL target chains, publicly");
        console2.log("destroy the deployer EOA private key. See BURN_CEREMONY.md");
    }
}
