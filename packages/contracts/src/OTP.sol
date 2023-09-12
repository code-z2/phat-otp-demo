// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "./PhatRollupAnchor.sol";

enum STATUSCODE {
    SUCCESS,
    FAILURE
}

struct OTPRecord {
    bytes32 otpHash;
    uint256 timestamp;
}

error InvalidSigner(address, address);

interface IOTP {
    event OTPReceived(bytes32, address indexed);

    function getOTP() external;

    function verifyOTP(bytes32 _otpHash, address recipient) external view returns (bool);
}

contract OTP is IOTP, PhatRollupAnchor {
    using ECDSA for bytes32;

    uint256 constant MAX_OTP_VALIDITY = 5 minutes;

    address public immutable _api;

    bool initialized = false;

    mapping(address => OTPRecord) public otpRecords;

    constructor(address api) {
        _api = api;
        _grantRole(PhatRollupAnchor.ATTESTOR_ROLE, api);
    }

    function setAttestor(address attester) public {
        require(!initialized, "OTP: already initialized.");
        _grantRole(PhatRollupAnchor.ATTESTOR_ROLE, attester);
        initialized = true;
    }

    function getOTP() public {
        _pushMessage(abi.encode(msg.sender, address(this)));
    }

    function verifyOTP(bytes32 _otpHash, address recipient) public view returns (bool) {
        OTPRecord memory otp = otpRecords[recipient];
        require(otp.otpHash == _otpHash, "OTP: Invalid otp.");
        require(block.timestamp <= otp.timestamp + MAX_OTP_VALIDITY, "OTP: validity expired.");
        return true;
    }

    function _setOtp(bytes32 _otp, address recipient) internal {
        otpRecords[recipient] = OTPRecord(_otp, block.timestamp);
        emit OTPReceived(_otp, recipient);
    }

    function _onMessageReceived(bytes calldata action) internal override {
        bytes32 otpHash = bytes32(action[0:32]);
        uint256 code = uint256(bytes32(action[32:64]));
        address recipient = address(bytes20(action[64:84]));
        bytes memory signature = action[84:];

        address signer = otpHash.toEthSignedMessageHash().recover(signature);
        if (signer != _api) {
            revert InvalidSigner(signer, _api);
        }
        if (code == uint256(STATUSCODE.SUCCESS) && recipient != address(0)) {
            _setOtp(otpHash, recipient);
        }
    }
}
