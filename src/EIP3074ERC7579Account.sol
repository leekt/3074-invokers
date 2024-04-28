// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Auth } from "./Auth.sol";
import { PackedUserOperation } from "./interfaces/PackedUserOperation.sol";
import { IValidator, IModule } from "./interfaces/IERC7579Modules.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import "forge-std/console.sol";
import { vToYParity } from "./utils.sol";

contract EIP3074ERC7579Account is Auth {
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
        address validator = address(bytes20(userOp.signature[0:20]));
        uint256 nonce = uint256(bytes32(userOp.signature[20:52]));
        (bytes calldata validatorData,, bytes calldata authSig) = parseSig(userOp.signature);

        bytes32 commit = keccak256(abi.encodePacked(validator, validatorData));
        bytes32 digest = getDigest(commit, nonce);
        address signer = ecrecover(digest, uint8(bytes1(authSig[64])), bytes32(authSig[0:32]), bytes32(authSig[32:64]));
        return caller == signer ? 0 : 1; // return true when caller == signer
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        address caller = address(bytes20(bytes32(userOp.nonce)));
        address validator = address(bytes20(userOp.signature[0:20]));
        (bytes calldata validatorData, bytes calldata validatorSig, bytes calldata authSig) = parseSig(userOp.signature);

        // do auth
        doAuth(caller, validator, validatorData, authSig);

        // do enable
        doEnable(validator, validatorData);

        // do validation
        PackedUserOperation memory op = userOp;
        op.signature = validatorSig;

        doValidation(validator, op, userOpHash);

        // do execute
        doExecute(userOp.callData[4:]);
    }

    function doAuth(address caller, address validator, bytes calldata validatorData, bytes calldata authSig) internal {
        bytes32 commit = keccak256(abi.encodePacked(validator, validatorData));
        Signature memory sig = Signature({
            signer: caller,
            yParity: vToYParity(uint8(bytes1(authSig[64]))),
            r: bytes32(authSig[0:32]),
            s: bytes32(authSig[32:64])
        });
        bool success = auth(commit, sig);
        require(success, "Auth failed");
    }

    function doEnable(address validator, bytes calldata validatorData) internal {
        bool success =
            authcall(validator, abi.encodeWithSelector(IModule.onInstall.selector, validatorData), 0, gasleft());
    }

    function doValidation(address validator, PackedUserOperation memory op, bytes32 userOpHash) internal {
        bool success = authcall(
            validator, abi.encodeWithSelector(IValidator.validateUserOp.selector, op, userOpHash), 0, gasleft()
        );
    }

    function doExecute(bytes calldata callData) internal {
        (address to, bytes memory data, uint256 value) = abi.decode(callData, (address, bytes, uint256));
        bool success = authcall(to, data, value, gasleft());
    }

    function parseSig(bytes calldata sig)
        internal
        pure
        returns (bytes calldata validatorData, bytes calldata validatorSig, bytes calldata authSig)
    {
        assembly {
            validatorData.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 52)))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            validatorSig.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 84)))
            validatorSig.length := calldataload(sub(validatorSig.offset, 32))
            authSig.offset := add(add(sig.offset, 84), calldataload(add(sig.offset, 116)))
            authSig.length := calldataload(sub(authSig.offset, 32))
        }
    }
}
