# Phat OTP

[workflow](https://bricks-poc5.phala.network/workflows/0x37d77f8f1164207c461a04687cb9b9a3c4cbffeb6bb03bc45c56d5594dc3dd48/1)

phat otp is an onchain otp verification contract leveraging phat functions.

a user can generate an otp sent to his xmtp inbox from a smart contract. and you can verify the otp within the specified validity period.

the contracts ignores requestId as only one otp record can exist for a user at a time. if a user makes two requests within the max-otp-validity period i.e 5 minutes. the latter otp overrides the former.

## challenges

due to technical challenges related to phat ABI Coders. (address coder, bytes32/fixedbytes coder). i.e so far, it could only work with uintcoder and bytescoder. I decided to relegated abi encoding and abi decoding to the otp server.

``

## structure

- api - an otp generating api, with the attestors private key, used to signer the otp hash, later to be verified onchain.
    . the otp's are not exposed onchain, only the hash of the otp can be sent onchain.

- contracts - the OTP contract inheriting the phalaAnchor contract

- core - the phat function.

## getting started

```sh
# clone this repo
# cd into it
pnpm install
make install target=contracts # install deps on the contract folder
# fill in all the required environment variables



# build the otp contract
make build target=contracts
# deploy the otp contract
cd packages/contracts
make deploy contract=OTP CHAIN=<MUMBAI | POLYGON> ## make sure to provide the required arguments



# start you server
cd packages/api
ts-node src/index.ts



# compile phat function
cd packages/core
# replace the api url with yours
pnpm build-functions
# run phat function
pnpm run-functions -a <abi.encoded(recipient, sender)> <api key>
# please refer to .env.examples to see the expected env variables
# deploy your functions
# deploy your api to cloud 
# enter the url in the phat-func
pnpm deploy-test-function # test for mumbai, main for polygon
# copy your attestor address, and set your attestor in the contract you deployed.

```
