pragma solidity ^0.8.0;

import { Auth } from "./Auth.sol";
import "./interfaces/IPaymaster.sol";
import "./interfaces/IEntryPoint.sol";
import "./utils.sol";

contract EIP3074Paymaster is IPaymaster, Auth {
    uint256 public constant PAYMASTER_VALIDATION_GAS_OFFSET = 20;
    uint256 public constant PAYMASTER_POSTOP_GAS_OFFSET = 36;
    uint256 public constant PAYMASTER_DATA_OFFSET = 52;

    IEntryPoint public immutable ep;

    constructor(IEntryPoint _ep) {
        ep = _ep;
    }

    function validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData)
    {
        bytes calldata data = userOp.paymasterAndData[PAYMASTER_DATA_OFFSET:];
        address caller = address(bytes20(data[0:20]));
        uint256 nonce = uint256(bytes32(data[20:52]));
        bytes32 digest = getDigest(userOpHash, nonce);
        address signer = ecrecover(
            digest,
            uint8(bytes1(userOp.signature[116])),
            bytes32(userOp.signature[52:84]),
            bytes32(userOp.signature[84:116])
        );
        return (
            abi.encodePacked(userOpHash, userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:]),
            signer == caller ? 0 : 1
        );
    }

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        external
    {
        uint256 postOpGas = uint256(uint128(bytes16(context[32:48]))) * actualUserOpFeePerGas;
        bytes32 userOpHash = bytes32(context[0:32]);
        bytes calldata data = context[48:];
        address caller = address(bytes20(data[0:20]));
        uint256 nonce = uint256(bytes32(data[20:52]));
        bytes32 digest = getDigest(userOpHash, nonce);
        Signature memory sig = Signature({
            signer: caller,
            yParity: vToYParity(uint8(bytes1(data[116]))),
            r: bytes32(data[52:84]),
            s: bytes32(data[84:116])
        });
        auth(userOpHash, sig);
        bool success = authcall(
            address(ep),
            abi.encodeWithSelector(IStakeManager.depositTo.selector, address(this)),
            postOpGas + actualGasCost,
            gasleft()
        );
        require(success, "auth call failed");
    }
}
