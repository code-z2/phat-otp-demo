# Phat OTP

phat otp is an onchain otp verification contract leveraging phat functions.

a user can generate an otp sent to his xmtp inbox from a smart contract. and can verify it during the specified validity period.

the contracts ignores requestId as only one otp record can exist for a user at a time. if a user makes two requests within the max-otp-validity period i.e 5 minutes. the latter otp overrides the former.

## challenges

due to technical challenges related to phat ABI Coders. (address coder, bytes32/fixedbytes coder). i.e so far, it could only work with uintcoder and bytescoder. i was not able to fully test it out as the affected coders which is heavily relied upon produces some errors:

``

## structure

- api - an otp generating api, with the attestors private key, used to signe the otp hash, later to be verified onchain.
    . the otp's are not exposed onchain, only the hash of the otp can be sent onchain.

- contracts - the OTP contract inheriting the phalaAnchor contract

- core - the phat function.

## getting started

```sh
# clone this repo

# cd into it

pnpm install

make install target=contracts # install deps on the contract folder

# build the otp contract

make build target=contracts

# deploy the otp contract

cd packages/contracts

make deploy ## make sure to provide the required arguments

# compile phat function

cd packages/core

pnpm build-functions

# run phat function

pnpm run-functions -a <your abi encoded recipient + sender> otp-api-key

# please refer to .env.examples to see the expected env variables
```
