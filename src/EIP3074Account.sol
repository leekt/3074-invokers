// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Auth } from "./Auth.sol";
import { PackedUserOperation } from "./interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import { vToYParity } from "./utils.sol";
import { MultiSendAuthCallOnly } from "./MultiSendAuthCallOnly.sol";

contract EIP3074Account is Auth {
    IEntryPoint public immutable ep;

    constructor(IEntryPoint _ep) {
        ep = _ep;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == address(ep), "!ep");
        address caller = address(bytes20(bytes32(userOp.nonce)));
        uint256 nonce = uint256(bytes32(userOp.signature[0:32]));
        bytes32 digest = getDigest(userOpHash, nonce);
        address signer = ecrecover(
            digest,
            uint8(bytes1(userOp.signature[96])),
            bytes32(userOp.signature[32:64]),
            bytes32(userOp.signature[64:96])
        );
        // NOTE : since auth is not allowed on validation phase, you should be have paymaster here, we don't send missingAccountFunds
        // But invoker can still pay for gas when someone staked for the invoker
        return caller == signer ? 0 : 1; // return true when caller == signer
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        address caller = address(bytes20(bytes32(userOp.nonce)));
        Signature memory sig = Signature({
            signer: caller,
            yParity: vToYParity(uint8(bytes1(userOp.signature[96]))),
            r: bytes32(userOp.signature[32:64]),
            s: bytes32(userOp.signature[64:96])
        });
        auth(userOpHash, sig);
        MultiSendAuthCallOnly.multiSend(userOp.callData[4:]);
    }
}
