// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/OTP.sol";

contract CounterTest is Test {
    OTP public otp;

    address alice = vm.createWallet("alice").addr;

    function setUp() public {
        otp = new OTP(alice);
    }
}
