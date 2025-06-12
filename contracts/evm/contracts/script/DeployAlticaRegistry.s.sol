// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/AlticaRegistry.sol"; // adjust path if needed

contract DeployAlticaRegistry is Script {
    function run() external {
        address deployer = vm.envAddress("DEPLOYER");

        vm.startBroadcast(deployer);

        AlticaRegistry registry = new AlticaRegistry();

        console.log("AlticaRegistry deployed to:", address(registry));

        vm.stopBroadcast();
    }
}
