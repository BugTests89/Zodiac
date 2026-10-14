// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "forge-std/console.sol";

contract VerifyABI is Script {
    function run() external view {
        console.log("=== ABI Verification ===");

        // 1. تأكد من الـ selectors
        console.log("isValidSignature(bytes32,bytes):");
        console.logBytes4(bytes4(keccak256("isValidSignature(bytes32,bytes)")));
        // متوقع: 0x1626ba7e

        console.log("isValidSignature(bytes,bytes):");
        console.logBytes4(bytes4(keccak256("isValidSignature(bytes,bytes)")));
        // متوقع: 0x20c13b0b

        console.log("execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool):");
        console.logBytes4(bytes4(keccak256(
            "execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool)"
        )));

        console.log("exploit(address,address,address,bytes32,uint256,address,uint256,bytes,uint8,bytes32):");
        console.logBytes4(bytes4(keccak256(
            "exploit(address,address,address,bytes32,uint256,address,uint256,bytes,uint8,bytes32)"
        )));

        console.log("transfer(address,uint256):");
        console.logBytes4(bytes4(keccak256("transfer(address,uint256)")));
        // متوقع: 0xa9059cbb

        console.log("balanceOf(address):");
        console.logBytes4(bytes4(keccak256("balanceOf(address)")));
        // متوقع: 0x70a08231

        console.log("=== Done ===");
    }
}
