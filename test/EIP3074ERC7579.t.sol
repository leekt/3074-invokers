pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/PackedUserOperation.sol";

import "src/EIP3074ERC7579Account.sol";
import "src/MockValidator.sol";
import { EntryPointLib } from "../src/erc4337Util.sol";

contract EIP3074Test is Test {
    address owner;
    uint256 ownerKey;
    IEntryPoint public ep;
    address payable bundler;

    EIP3074ERC7579Account account;
    MockValidator mockValidator;
    uint8 AUTHCALL_IDENTIFIER = 2;

    function setUp() external {
        ep = IEntryPoint(EntryPointLib.deploy());
        (owner, ownerKey) = makeAddrAndKey("Owner");
        account = new EIP3074ERC7579Account(ep);
        mockValidator = new MockValidator();
        bundler = payable(makeAddr("Bundler"));
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
            callData: abi.encodePacked(
                account.executeUserOp.selector,
                abi.encodePacked(AUTHCALL_IDENTIFIER, address(to), uint256(value), data.length, data)
            ),
            paymasterAndData: hex"",
            gasFees: bytes32(0),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            signature: abi.encodePacked(
                address(mockValidator), uint256(0), abi.encode(hex"deadbeef", hex"cafecafe", abi.encodePacked(r, s, v))
            )
        });
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        ep.handleOps(ops, bundler);
        require(to.balance == 1);
    }
}
