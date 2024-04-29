// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Auth } from "./Auth.sol";
import { PackedUserOperation } from "./interfaces/PackedUserOperation.sol";
import { IPolicy, ISigner, IModule } from "./interfaces/IERC7579Modules.sol";
import { IEntryPoint } from "./interfaces/IEntryPoint.sol";
import "forge-std/console.sol";
import "./utils.sol";
import { MultiSendAuthCallOnly } from "./MultiSendAuthCallOnly.sol";
/*
    TODO
    - add hook support
    - merge with https://github.com/thogard785/generalized-interpretable-invoker/tree/main to serve the same role
    - add staking support
    Optional
    - add pre-deposit wrapped ETH?
 */

struct PermissionConfig {
    bool enabled;
    uint256 nonce;
    IPolicy[] policies; // all policies should be used with userOp validation
    ISigner signer;
}

contract EIP3074PermissionsAccount is Auth {
    IEntryPoint public immutable ep;

    error OutOfTimeRange();

    mapping(address authority => mapping(bytes12 permissionId => PermissionConfig)) public permissionConfig;

    mapping(address authority => uint256) public lastNonce;

    constructor(IEntryPoint _ep) {
        ep = _ep;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == address(ep), "!ep");
        bytes12 permissionId = bytes12(userOp.signature[0:12]);
        uint256 authNonce = uint256(bytes32(userOp.signature[12:44]));
        address authority = address(bytes20(bytes32(userOp.nonce))); // we have 4 bytes for parallel nonce (2**32)
        if(authNonce < lastNonce[authority]) {
            // when authNonce is lower than lastNonce, we can guarantee it's not working
            revert NonceTooLow();
        }
        (bytes calldata permissionData, bytes calldata permissionSig, bytes calldata authSig) = parseSig(userOp.signature[44:])
        if(!permissionConfig[authority][permissionId].enabled) {
            // enable mode
            // check permissionId matches the keccak256(permissionData)
            bytes12 calculatedId = getPermissionId(permissionData, authNonce);
            if(calculatedId != permissionId) {
                revert PermissionIdMismatch();
            }
            // verify authSig is signed by authority
            if(!checkAuthSig(authority, getDigest(bytes32(permissionId), authNonce), authSig)) {
                revert InvalidAuthSig();
            }
            // enable permission
        } else {
            // check authNonce matches the nonce stored on permissionConfig

        }
        return _permissionValidation(authority, permissionId, permissionSig);
    }

    function _permissionValidation(address authority, bytes12 permissionId, bytes calldata permissionSig) internal returns(uint256) {
        bytes32 id = bytes32(abi.encodePacked(authority, permissionId)); // TODO: make this assembly
        bytes[] memory sig = abi.decode(permissionSig, (bytes[]));
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        address authority = address(bytes20(bytes32(userOp.nonce)));
        // do auth
        setAuth(authority, validatorData, authSig);

        // do execute
        // NOTE : this will make some incompatibility with 7579 accounts,
        // hooks that does not rely on the 7579 account interface will be compatible atm, but this can be fixed
        execute(userOp.callData[4:]);
    }

    function setAuth(address authority, bytes calldata validatorData, bytes calldata authSig) internal {
        bytes32 commit = keccak256(abi.encodePacked(validatorData));
        Signature memory sig = Signature({
            signer: authority,
            yParity: vToYParity(uint8(bytes1(authSig[64]))),
            r: bytes32(authSig[0:32]),
            s: bytes32(authSig[32:64])
        });
        bool success = auth(commit, sig);
        require(success, "Auth failed");
    }

    function execute(bytes calldata callData) internal {
        MultiSendAuthCallOnly.multiSend(callData);
    }

    function parseSig(bytes calldata sig)
        internal
        pure
        returns (bytes calldata validatorData, bytes calldata validatorSig, bytes calldata authSig)
    {
        assembly {
            validatorData.offset := add(add(sig.offset, 32), calldataload(sig.offset))
            validatorData.length := calldataload(sub(validatorData.offset, 32))
            validatorSig.offset := add(add(sig.offset, 32), calldataload(add(sig.offset, 32)))
            validatorSig.length := calldataload(sub(validatorSig.offset, 32))
            authSig.offset := add(add(sig.offset, 32), calldataload(add(sig.offset, 64)))
            authSig.length := calldataload(sub(authSig.offset, 32))
        }
    }
}
