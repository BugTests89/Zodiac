// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IStkAAVE {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
