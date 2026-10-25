// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CX} from "../contracts/CX.sol";
import {AbstractICApp} from "../contracts/apps/AbstractICApp.sol";
import {ITokenRecipient} from "../contracts/apps/interfaces/ITokenRecipient.sol";
import {TokenMessageLib} from "../contracts/apps/libs/TokenMessage.sol";
import {IInterchainAppV1} from "../contracts/interfaces/IInterchainAppV1.sol";

/// @notice Fork-based test of the HIGH-risk findings:
///   (1) unlimited mint / role escalation
///   (2) bridge takeover through IC_GOVERNOR_ROLE (clients, linked app, modules, guard)
///   (3) burnAllocation abuse
/// Goal: prove an OUTSIDER (no role) or a MALICIOUS CONTRACT cannot exploit them,
/// and document (CONTROL tests) what happens when a privileged key is compromised.
///
/// Run:  RPC_URL=<mainnet rpc> forge test --match-contract CXHighRisk -vvv
/// Optional: FORK_BLOCK=<n>  to pin the block.

// ───────────────────────────── helpers ─────────────────────────────

/// Stand-in for a legit InterchainClient: just forwards appReceive.
contract MockClient {
    function deliver(CX app, uint64 src, bytes32 sender, uint64 nonce, bytes calldata message) external {
        app.appReceive(src, sender, nonce, message);
    }
}

/// Malicious contract that tries every entry point without being a registered client.
contract EvilCaller {
    function attackAppReceive(CX app, uint64 src, bytes32 sender, uint256 amount) external {
        app.appReceive(src, sender, 1, TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(address(this)))), amount));
    }
}

/// Malicious hook recipient: when it receives tokens, it tries to escalate inside the hook.
contract EvilRecipient is ITokenRecipient {
    CX public immutable cx;
    bool public mintWorked;
    bool public grantWorked;
    bool public reenterWorked;
    bool public burnAllocWorked;
    bool public hookCalled;
    uint64 public srcChain;
    bytes32 public linkedSender;

    constructor(CX cx_, uint64 src_, bytes32 sender_) {
        cx = cx_;
        srcChain = src_;
        linkedSender = sender_;
    }

    function onICTokenReceived(address, uint256, bytes memory) external override {
        hookCalled = true;
        try cx.mint(address(this), 1e30) { mintWorked = true; } catch {}
        try cx.grantRole(cx.MINTER_ROLE(), address(this)) { grantWorked = true; } catch {}
        try cx.burnAllocation(address(0xdead), 1) { burnAllocWorked = true; } catch {}
        // Re-enter appReceive pretending to be the client with the right linked sender.
        try cx.appReceive(
            srcChain, linkedSender, 99, TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(address(this)))), 1e30)
        ) {
            reenterWorked = true;
        } catch {}
    }
}

// ───────────────────────────── tests ─────────────────────────────

contract CXHighRiskForkTest is Test {
    CX internal cx;
    MockClient internal client;

    address internal admin = makeAddr("admin");
    address internal governance = makeAddr("governance");
    address internal minter = makeAddr("minter");
    address internal icGov = makeAddr("icGovernor");
    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");

    uint64 internal remoteChain;
    bytes32 internal remoteApp = bytes32(uint256(uint160(address(0xBEEF))));

    function setUp() public {
        // Fork (skipped automatically if RPC_URL is not set, so the file still runs locally).
        string memory rpc = vm.envOr("RPC_URL", string(""));
        if (bytes(rpc).length != 0) {
            uint256 blk = vm.envOr("FORK_BLOCK", uint256(0));
            if (blk == 0) vm.createSelectFork(rpc);
            else vm.createSelectFork(rpc, blk);
        }

        remoteChain = uint64(block.chainid) + 1;

        cx = new CX(admin);
        client = new MockClient();

        vm.startPrank(admin);
        cx.grantRole(cx.GOVERNANCE_ROLE(), governance);
        cx.grantRole(cx.MINTER_ROLE(), minter);
        cx.grantRole(cx.IC_GOVERNOR_ROLE(), icGov);
        vm.stopPrank();

        vm.startPrank(icGov);
        cx.addInterchainClient(address(client), true);
        cx.linkRemoteApp(remoteChain, remoteApp);
        vm.stopPrank();

        vm.prank(governance);
        cx.enableTransfers();
    }

    function _unauth(address who, bytes32 role) internal {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who, role));
    }

    // ═════════ HIGH 1: unlimited mint / role escalation ═════════

    function test_outsider_cannot_mint() public {
        bytes32 r = cx.MINTER_ROLE();
        vm.startPrank(attacker);
        _unauth(attacker, r);
        cx.mint(attacker, type(uint208).max);
        vm.stopPrank();
        assertEq(cx.totalSupply(), 0);
    }

    function test_outsider_cannot_selfGrantAnyRole() public {
        bytes32 adminRole = cx.DEFAULT_ADMIN_ROLE();
        bytes32[4] memory roles =
            [cx.MINTER_ROLE(), cx.GOVERNANCE_ROLE(), cx.IC_GOVERNOR_ROLE(), cx.DEFAULT_ADMIN_ROLE()];
        for (uint256 i; i < roles.length; ++i) {
            vm.prank(attacker);
            _unauth(attacker, adminRole);
            cx.grantRole(roles[i], attacker);
            assertFalse(cx.hasRole(roles[i], attacker));
        }
    }

    function test_minter_cannot_escalate_to_other_roles() public {
        bytes32 adminRole = cx.DEFAULT_ADMIN_ROLE();
        vm.startPrank(minter);
        _unauth(minter, adminRole);
        cx.grantRole(cx.IC_GOVERNOR_ROLE(), minter);
        vm.stopPrank();
    }

    function testFuzz_random_caller_cannot_mint(address who, uint256 amount) public {
        vm.assume(who != minter && who != admin && who != address(0));
        vm.prank(who);
        vm.expectRevert();
        cx.mint(who, amount);
    }

    // ═════════ HIGH 2: bridge takeover (IC_GOVERNOR_ROLE) ═════════

    function test_outsider_cannot_touch_any_bridge_setting() public {
        bytes32 r = cx.IC_GOVERNOR_ROLE();
        vm.startPrank(attacker);

        _unauth(attacker, r);
        cx.addInterchainClient(attacker, true);
        _unauth(attacker, r);
        cx.removeInterchainClient(address(client));
        _unauth(attacker, r);
        cx.setLatestInterchainClient(address(0));
        _unauth(attacker, r);
        cx.linkRemoteApp(remoteChain, bytes32(uint256(uint160(attacker))));
        _unauth(attacker, r);
        cx.linkRemoteAppEVM(remoteChain, attacker);
        _unauth(attacker, r);
        cx.addTrustedModule(attacker);
        _unauth(attacker, r);
        cx.removeTrustedModule(attacker);
        _unauth(attacker, r);
        cx.setGuardConfig(0, address(0), 0);
        _unauth(attacker, r);
        cx.setRequiredResponses(0);
        _unauth(attacker, r);
        cx.setExecutionService(attacker);
        _unauth(attacker, r);
        cx.setGasLimit(remoteChain, 1);
        _unauth(attacker, r);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.LinkRemoteApp);
        _unauth(attacker, r);
        cx.freezeLinkedApp(remoteChain);

        vm.stopPrank();

        // State unchanged
        assertEq(cx.getLinkedApp(remoteChain), remoteApp);
        assertEq(cx.getLatestInterchainClient(), address(client));
    }

    function test_malicious_contract_cannot_call_appReceive_directly() public {
        EvilCaller evil = new EvilCaller();
        vm.expectRevert(
            abi.encodeWithSelector(AbstractICApp.InterchainApp__NotInterchainClient.selector, address(evil))
        );
        evil.attackAppReceive(cx, remoteChain, remoteApp, 1_000_000e18);
        assertEq(cx.totalSupply(), 0);
    }

    function test_attacker_deployed_client_is_rejected() public {
        vm.startPrank(attacker);
        MockClient fake = new MockClient();
        bytes memory m = TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(attacker))), 1e24);
        vm.expectRevert(abi.encodeWithSelector(AbstractICApp.InterchainApp__NotInterchainClient.selector, address(fake)));
        fake.deliver(cx, remoteChain, remoteApp, 1, m);
        vm.stopPrank();
        assertEq(cx.balanceOf(attacker), 0);
    }

    function test_registered_client_but_spoofed_sender_is_rejected() public {
        bytes32 spoof = bytes32(uint256(uint160(attacker)));
        bytes memory m = TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(attacker))), 1e24);
        vm.expectRevert(
            abi.encodeWithSelector(AbstractICApp.InterchainApp__SrcSenderNotAllowed.selector, remoteChain, spoof)
        );
        client.deliver(cx, remoteChain, spoof, 1, m);
    }

    function test_unlinked_chain_is_rejected() public {
        uint64 other = remoteChain + 7;
        bytes memory m = TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(attacker))), 1e24);
        vm.expectRevert(); // sender (any) != linkedApp(0)
        client.deliver(cx, other, remoteApp, 1, m);
    }

    function test_local_chainid_as_source_is_rejected() public {
        bytes memory m = TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(attacker))), 1e24);
        vm.expectRevert(
            abi.encodeWithSelector(AbstractICApp.InterchainApp__ChainIdNotRemote.selector, uint64(block.chainid))
        );
        client.deliver(cx, uint64(block.chainid), remoteApp, 1, m);
    }

    function test_malicious_hook_recipient_cannot_escalate() public {
        EvilRecipient evil = new EvilRecipient(cx, remoteChain, remoteApp);
        uint256 amt = 100e18;
        bytes memory m = TokenMessageLib.encodeHookMessage(bytes32(uint256(uint160(address(evil)))), amt, hex"1234");

        client.deliver(cx, remoteChain, remoteApp, 1, m); // legit delivery

        assertTrue(evil.hookCalled(), "hook not reached");
        assertFalse(evil.mintWorked(), "hook minted!");
        assertFalse(evil.grantWorked(), "hook granted role!");
        assertFalse(evil.reenterWorked(), "hook re-entered appReceive!");
        assertFalse(evil.burnAllocWorked(), "hook burned allocation!");
        assertEq(cx.balanceOf(address(evil)), amt);
        assertEq(cx.totalSupply(), amt);
    }

    // ═════════ HIGH 3: burnAllocation ═════════

    function test_outsider_cannot_burnAllocation() public {
        // Use a fresh instance where transfers are still disabled (the only state in which it is callable).
        CX fresh = new CX(admin);
        vm.startPrank(admin);
        fresh.grantRole(fresh.GOVERNANCE_ROLE(), governance);
        fresh.grantRole(fresh.MINTER_ROLE(), minter);
        vm.stopPrank();
        vm.prank(minter);
        fresh.mint(victim, 1000e18);

        bytes32 r = fresh.GOVERNANCE_ROLE();
        vm.startPrank(attacker);
        _unauth(attacker, r);
        fresh.burnAllocation(victim, 1000e18);
        vm.stopPrank();
        assertEq(fresh.balanceOf(victim), 1000e18);
    }

    function test_burnAllocation_impossible_after_transfers_enabled() public {
        vm.prank(minter);
        cx.mint(victim, 1000e18);
        vm.prank(governance); // even governance itself
        vm.expectRevert(CX.CX__TransfersEnabled.selector);
        cx.burnAllocation(victim, 1000e18);
        assertEq(cx.balanceOf(victim), 1000e18);
    }

    function test_burnFrom_without_allowance_reverts() public {
        vm.prank(minter);
        cx.mint(victim, 1000e18);
        vm.prank(attacker);
        vm.expectRevert();
        cx.burnFrom(victim, 1);
    }

    // ═════════ CONTROL tests: what a COMPROMISED privileged key can do ═════════
    // These are EXPECTED TO SUCCEED. They document the trust boundary, they are not bugs in the test.

    function test_CONTROL_compromised_minter_mints_unbounded() public {
        vm.prank(minter);
        cx.mint(attacker, type(uint128).max);
        assertEq(cx.balanceOf(attacker), type(uint128).max); // no supply cap exists
    }

    function test_CONTROL_compromised_icGovernor_can_mint_via_malicious_client() public {
        vm.startPrank(icGov);
        MockClient evilClient = new MockClient();
        cx.addInterchainClient(address(evilClient), false);
        vm.stopPrank();

        bytes memory m = TokenMessageLib.encodeBasicMessage(bytes32(uint256(uint160(attacker))), 1e30);
        evilClient.deliver(cx, remoteChain, remoteApp, 1, m);
        assertEq(cx.balanceOf(attacker), 1e30); // full takeover with only IC_GOVERNOR_ROLE
    }

    function test_CONTROL_freezing_actions_closes_the_takeover_path() public {
        vm.startPrank(icGov);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.AddInterchainClient);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.LinkRemoteApp);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.AddTrustedModule);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.SetGuardConfig);
        cx.freezeGovernorAction(IInterchainAppV1.GovernorAction.SetRequiredResponses);

        MockClient evilClient = new MockClient();
        vm.expectRevert(IInterchainAppV1.InterchainApp__GovernorActionFrozen.selector);
        cx.addInterchainClient(address(evilClient), false);

        vm.expectRevert(IInterchainAppV1.InterchainApp__GovernorActionFrozen.selector);
        cx.linkRemoteApp(remoteChain, bytes32(uint256(uint160(attacker))));
        vm.stopPrank();
    }

    function test_CONTROL_compromised_governance_burns_while_transfers_disabled() public {
        CX fresh = new CX(admin);
        vm.startPrank(admin);
        fresh.grantRole(fresh.GOVERNANCE_ROLE(), governance);
        fresh.grantRole(fresh.MINTER_ROLE(), minter);
        vm.stopPrank();
        vm.prank(minter);
        fresh.mint(victim, 1000e18);
        vm.prank(governance);
        fresh.burnAllocation(victim, 1000e18);
        assertEq(fresh.balanceOf(victim), 0);
    }
}
