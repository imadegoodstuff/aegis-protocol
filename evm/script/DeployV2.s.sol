// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import {SphincsVerifierStub}    from "../src/SphincsVerifierStub.sol";
import {SphincsC13Verifier}     from "../src/SphincsC13Verifier.sol";
import {AegisAccountV2Factory}  from "../src/AegisAccountV2Factory.sol";
import {UpgradeHelper}          from "../src/UpgradeHelper.sol";
import {ISphincsVerifier}       from "../src/interfaces/ISphincsVerifier.sol";

/// Deploys the V2 stack: Verifier + Factory + UpgradeHelper.
///
/// Env:
///   AEGIS_DEPLOYER_KEY    hex private key (fresh EOA, nonce 0)
///   AEGIS_FEE_COLLECTOR   immutable fee recipient (any address)
///   AEGIS_VERIFIER        "prod" (C13, 1.5M gas) or "stub" (cheap, insecure)
contract DeployV2 is Script {
    function run() external returns (address verifier, address factory, address helper) {
        address feeCollector = vm.envAddress("AEGIS_FEE_COLLECTOR");
        string memory kind   = vm.envOr("AEGIS_VERIFIER", string("stub"));
        uint256 pk           = vm.envUint("AEGIS_DEPLOYER_KEY");

        vm.startBroadcast(pk);

        // nonce 0 -> Verifier
        if (keccak256(bytes(kind)) == keccak256(bytes("stub"))) {
            verifier = address(new SphincsVerifierStub());
        } else {
            verifier = address(new SphincsC13Verifier());
        }

        // nonce 1 -> Factory
        factory = address(new AegisAccountV2Factory(ISphincsVerifier(verifier), feeCollector));

        // nonce 2 -> UpgradeHelper
        helper = address(new UpgradeHelper(AegisAccountV2Factory(factory)));

        vm.stopBroadcast();

        console2.log("chain id       :", block.chainid);
        console2.log("verifier kind  :", kind);
        console2.log("verifier       :", verifier);
        console2.log("factory        :", factory);
        console2.log("upgrade helper :", helper);
        console2.log("fee collector  :", feeCollector);
    }
}
