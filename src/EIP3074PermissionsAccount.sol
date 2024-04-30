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
    - merge with https://github.com/thogard785/generalized-interpretable-invoker/tree/main to serve the same role
    - add staking support
    Optional
    - add pre-deposit wrapped ETH?
 */

struct PermissionConfig {
    bool enabled;
    bytes32 digest;
    uint256 nonce;
    IPolicy[] policies; // all policies should be used with userOp validation
    ISigner signer;
}

contract EIP3074PermissionsAccount is Auth {
    IEntryPoint public immutable ep;

    error OutOfTimeRange();
    error NonceTooLow();
    error NonceMismatch();
    error PermissionIdMismatch();
    error InvalidAuthSig();
    error BlockedByPolicy(uint256 i);

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
        if (authNonce < lastNonce[authority]) {
            // when authNonce is lower than lastNonce, we can guarantee it's not working
            revert NonceTooLow();
        }
        bytes calldata permissionSig = userOp.signature[44:];
        if (!permissionConfig[authority][permissionId].enabled) {
            // on enable mode
            bytes calldata permissionData;
            bytes calldata authSig;
            (permissionData, permissionSig, authSig) = parseSig(userOp.signature[44:]);
            // enable mode
            // check permissionId matches the keccak256(permissionData)
            bytes12 calculatedId = getPermissionId(permissionData, authNonce);
            if (calculatedId != permissionId) {
                revert PermissionIdMismatch();
            }
            bytes32 commit = getDigest(bytes32(permissionId), authNonce);
            // verify authSig is signed by authority
            if (!checkAuthSig(authority, commit, authSig)) {
                revert InvalidAuthSig();
            }
            // enable permission
            _enablePermission(authority, authNonce, permissionId, permissionData);
        } else {
            // check authNonce matches the nonce stored on permissionConfig
            if (authNonce != permissionConfig[authority][permissionId].nonce) {
                revert NonceMismatch();
            }
        }
        return _permissionValidation(userOp, userOpHash, authority, permissionId, permissionSig);
    }

    function _enablePermission(
        address authority,
        uint256 authNonce,
        bytes12 permissionId,
        bytes calldata permissionData
    ) internal {
        PermissionConfig storage config = permissionConfig[authority][permissionId];
        config.nonce = authNonce;
        bytes[] calldata data = toBytesArray(permissionData);
        uint256 i;
        for (i = 0; i < data.length - 1; i++) {
            address module = address(bytes20(data[i][0:20]));
            config.policies.push(IPolicy(module));
            bytes calldata installData = data[i][20:];
            IModule(module).onInstall(installData);
        }
    }

    function _permissionValidation(
        PackedUserOperation calldata op,
        bytes32 userOpHash,
        address authority,
        bytes12 permissionId,
        bytes calldata permissionSig
    ) internal returns (uint256) {
        bytes32 id = bytes32(abi.encodePacked(authority, permissionId)); // TODO: make this assembly
        bytes[] calldata data = toBytesArray(permissionSig);
        IPolicy[] memory policies = permissionConfig[authority][permissionId].policies;
        PackedUserOperation memory mOp = op; // NOTE: mOp does not change the userOp.sender, just in case ;)
        require(data.length == policies.length + 1, "data array has to be same as policies length + 1");
        for (uint256 i = 0; i < policies.length; i++) {
            mOp.signature = data[i];
            uint256 res = policies[i].checkUserOpPolicy(id, mOp);
            if (res != 0) {
                // TODO: we will deal with time frame later
                revert BlockedByPolicy(i);
            }
        }

        ISigner signer = permissionConfig[authority][permissionId].signer;
        mOp.signature = data[data.length - 1];
        return signer.checkUserOpSignature(id, mOp, userOpHash);
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external {
        require(msg.sender == address(ep), "!ep");
        address authority = address(bytes20(bytes32(userOp.nonce)));
        bytes12 permissionId = bytes12(userOp.signature[0:12]);
        uint256 authNonce = uint256(bytes32(userOp.signature[12:44]));
        bytes32 digest = getDigest(bytes32(permissionId), authNonce);
        (,, bytes calldata authSig) = parseSig(userOp.signature[44:]);
        // do auth
        setAuth(authority, digest, authSig);

        // do execute
        // NOTE : this will make some incompatibility with 7579 accounts,
        // hooks that does not rely on the 7579 account interface will be compatible atm, but this can be fixed
        execute(userOp.callData[4:]);
    }

    function setAuth(address authority, bytes32 commit, bytes calldata authSig) internal {
        Signature memory sig = Signature({
            signer: authority,
            yParity: vToYParity(uint8(bytes1(authSig[64]))),
            r: bytes32(authSig[0:32]),
            s: bytes32(authSig[32:64])
        });
        bool success = auth(commit, sig);
        require(success, "Auth failed");
    }

    function checkAuthSig(address authority, bytes32 digest, bytes calldata authSig) internal view returns (bool) {
        address signer = ecrecover(
            digest,
            uint8(bytes1(authSig[64])), // NOTE: v value has to be 27 or 28, this will be shifted to 0 or 1 on setAuth() to match the 3074 mechanism
            bytes32(authSig[0:32]),
            bytes32(authSig[32:64])
        );
        return signer == authority;
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

    function getPermissionId(bytes calldata permissionData, uint256 nonce) internal returns (bytes12) {
        return bytes12(keccak256(abi.encodePacked(permissionData, nonce)));
    }

    function toBytesArray(bytes calldata data) internal returns (bytes[] calldata res) {
        assembly {
            res.offset := add(add(data.offset, 32), calldataload(data.offset))
            res.length := calldataload(sub(res.offset, 32))
        }
    }
}
