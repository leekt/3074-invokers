pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/PackedUserOperation.sol";

import "src/EIP3074ERC7579Account.sol";
import "src/MockValidator.sol";

contract EIP3074Test is Test {
    address owner;
    uint256 ownerKey;

    EIP3074ERC7579Account account;
    MockValidator mockValidator;

    function setUp() external {
        (owner, ownerKey) = makeAddrAndKey("Owner");
        account = new EIP3074ERC7579Account();
        mockValidator = new MockValidator();
    }

    function testSign() external {
        vm.deal(address(account), 1e18);
        vm.deal(address(owner), 2);
        console.log("Owner :", owner);
        bytes32 digest = account.getDigest(keccak256(abi.encodePacked(mockValidator, hex"deadbeef")), 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        address to = address(0xdeadbeef);
        bytes memory data = hex"";
        uint256 value = 1;
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(account),
            nonce: uint256(bytes32(bytes20(address(owner)))),
            initCode: hex"",
            callData: abi.encodePacked(account.executeUserOp.selector, abi.encode(to, data, value)),
            paymasterAndData: hex"",
            gasFees: bytes32(0),
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            signature: abi.encodePacked(
                address(mockValidator), uint256(0), abi.encode(hex"deadbeef", hex"cafecafe", abi.encodePacked(r, s, v))
                )
        });
        account.validateUserOp(op, bytes32(keccak256(hex"deadbeef")), 0);
        account.executeUserOp(op, bytes32(keccak256(hex"deadbeef")));
        require(to.balance == 1);
    }
}
