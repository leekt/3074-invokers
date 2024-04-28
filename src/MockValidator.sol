pragma solidity ^0.8.0;

import { IValidator } from "./interfaces/IERC7579Modules.sol";
import { PackedUserOperation } from "./interfaces/PackedUserOperation.sol";

contract MockValidator is IValidator {
    mapping(address caller => bytes) public data;

    mapping(address caller => bytes32) public lastHash;

    function onInstall(bytes calldata _data) external payable {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable {
        delete data[msg.sender];
    }

    function isInitialized(address _caller) external view returns (bool) {
        return data[_caller].length > 0;
    }

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {
        return moduleTypeId == 1;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32 hash) external payable returns (uint256) {
        lastHash[msg.sender] = hash;
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external view returns (bytes4) {
        return 0xffffffff;
    }
}
