pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/interfaces/PackedUserOperation.sol";

import "src/EIP3074PermissionsAccount.sol";
import "src/MockPolicy.sol";
import "src/MockSigner.sol";
import { EntryPointLib } from "../src/erc4337Util.sol";

contract EIP3074Test is Test {
    address owner;
    uint256 ownerKey;
    IEntryPoint public ep;
    address payable bundler;

    EIP3074PermissionsAccount account;
    MockPolicy mockPolicy;
    MockSigner mockSigner;
    uint8 AUTHCALL_IDENTIFIER = 2;

    function setUp() external {
        ep = IEntryPoint(EntryPointLib.deploy());
        (owner, ownerKey) = makeAddrAndKey("Owner");
        account = new EIP3074PermissionsAccount(ep);
        mockPolicy = new MockPolicy();
        mockSigner = new MockSigner();
        bundler = payable(makeAddr("Bundler"));
    }

    function testSign() external {
        vm.deal(address(account), 1e18);
        vm.deal(address(owner), 2);
        console.log("Owner :", owner);
        bytes[] memory policyAndSignerData = new bytes[](2);
        policyAndSignerData[0] = abi.encodePacked(mockPolicy, "policyData");
        policyAndSignerData[1] = abi.encodePacked(mockSigner, "signerData");
        bytes[] memory policyAndSignerSig = new bytes[](2);
        policyAndSignerSig[0] = abi.encodePacked("policySig");
        policyAndSignerSig[1] = abi.encodePacked("signerSig");
        uint256 authNonce = 0;
        bytes12 permissionId = account.getPermissionId(abi.encode(policyAndSignerData), authNonce);
        bytes32 digest = account.getDigest(bytes32(permissionId), authNonce); // TODO: use nonce only once
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest); // this is authSig
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
                permissionId,
                authNonce,
                abi.encode(abi.encode(policyAndSignerData), abi.encode(policyAndSignerSig), abi.encodePacked(r, s, v))
                )
        });
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        mockPolicy.sudoSetValidSig(address(account), bytes32(abi.encodePacked(address(owner), permissionId)), "policySig");
        mockSigner.sudoSetValidSig(address(account), bytes32(abi.encodePacked(address(owner), permissionId)), "signerSig");

        ep.handleOps(ops, bundler);
        require(to.balance == 1);
    }
}
