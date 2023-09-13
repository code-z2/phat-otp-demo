# Phat OTP

[workflow phala testnet](https://bricks-poc5.phala.network/workflows/0x37d77f8f1164207c461a04687cb9b9a3c4cbffeb6bb03bc45c56d5594dc3dd48/2)

[consumer contract mumbai](https://mumbai.polygonscan.com/address/0x3591fdecbcbd75db9ee5786aef3aa76573946f0d)

[workflow phala  mainnet](https://bricks.phala.network/workflows/0x4f3c6b9b59c9760ce8b2fd6f393c9e82ffba6a02e20383ea7883d5115d05d3de/0)

[consumer contract polygon](https://polygonscan.com/address/0x5b900b1a053b26b3900242222a51613b9ee98a18)

[verifying otp on-chain: tutorial article](https://mirror.xyz/anyaogu.eth/5Ejt15zwbVokWlD32fPY8cJFmU5w0rmkmiC2XG_fmmI)

phat OTP is an on-chain OTP verification contract leveraging phat functions.

A user can generate an OTP sent to his XMTP inbox from a smart contract. and you can verify the OTP within the specified validity period.

The contract ignores requestId as only one OTP record can exist for a user at a time. if a user makes two requests within the max-OTP-validity period i.e. 5 minutes. The latter OTP overrides the former.

## structure

- API - an OTP generating API, with the API private key, used to signer the OTP hash, later to be verified on-chain. The OTP's are not exposed on-chain, only the hash of the OTP can be sent on-chain.

- contracts - the OTP contract inheriting the `PhalaRollupAnchor` contract

- core - the phat function.

## getting started

```sh
# clone this repo
# cd into it
pnpm install
make install target=contracts # install deps on the contract folder


# fill in all the required environment variables
# you can copy all .env.examples for a start


# build the OTP contract
make build target=contracts
# deploy the OTP contract
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
# test locally
# you need to make sure your local api url is specified in phat function
pnpm localhost-test



# deploy your functions
# please refer to .env.examples to see the expected env variables
# make sure your api is deployed to cloud 
# enter the url in the phat-func
pnpm deploy-test-function # for phala testnet
pnpm deploy-main-function # for phala mainnet
# copy your attestor address, and set your attestor in the contract you deployed.
```

phat otp mainnet deploy log
![mainnet deployment](mainnet%20deployment.png)
