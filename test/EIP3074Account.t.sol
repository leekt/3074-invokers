// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { VmSafe } from "forge-std/Vm.sol";
import { Auth } from "../src/Auth.sol";
import { EIP3074Account } from "../src/EIP3074Account.sol";
import { vToYParity } from "./utils.sol";
import { PackedUserOperation } from "../src/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "../src/interfaces/IEntryPoint.sol";
import { EntryPointLib } from "../src/erc4337Util.sol";

contract Callee {
    error UnexpectedSender(address expected, address actual);

    mapping(address => uint256) public counter;
    mapping(address => uint256) public values;

    function increment() public payable {
        counter[msg.sender] += 1;
        values[msg.sender] += msg.value;
    }

    function expectSender(address expected) public payable {
        if (msg.sender != expected) revert UnexpectedSender(expected, msg.sender);
    }
}

contract EIP3074AccountTest is Test {
    Callee public callee;
    EIP3074Account public invoker;
    IEntryPoint public ep;
    address owner;
    uint256 ownerKey;

    address payable bundler;

    uint8 AUTHCALL_IDENTIFIER = 2;

    function setUp() public {
        ep = IEntryPoint(EntryPointLib.deploy());
        invoker = new EIP3074Account(ep);
        callee = new Callee();
        (owner, ownerKey) = makeAddrAndKey("Owner");
        bundler = payable(makeAddr("Bundler"));
    }

    function test_execute_withData() external {
        vm.deal(address(invoker), 1e18);
        vm.deal(address(owner), 2);
        uint256 nonce = 0;
        bytes memory data = abi.encodePacked(
            invoker.executeUserOp.selector,
            abi.encode(
                address(callee),
                abi.encodeWithSelector(Callee.increment.selector),
                0
            )
        );
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(invoker),
            nonce: uint256(bytes32(bytes20(address(owner)))),
            initCode: hex"",
            callData: data,
            paymasterAndData: hex"",
            gasFees: bytes32(0),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            signature: hex"" 
        });

        bytes32 userOpHash = ep.getUserOpHash(op);
        bytes32 hash = invoker.getDigest(userOpHash, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        op.signature = abi.encodePacked(nonce, r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        ep.handleOps(ops, bundler);
        //invoker.validateUserOp(op, userOpHash, 0);
        //invoker.executeUserOp(op, userOpHash);
        assertEq(callee.counter(owner), 1);
    }

}
