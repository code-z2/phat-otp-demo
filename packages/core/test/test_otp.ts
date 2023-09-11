import {expect} from "chai"
import {type Contract, type Event} from "ethers"
import {ethers} from "hardhat"
import {execSync} from "child_process"
import {Coders} from "@phala/ethers"
import BYTECODE__ABI from "../abis/bytecode_abi.json"

type HexString = `0x${string}`

const address = new Coders.AddressCoder("address")

function abiCoder() {
    return Coders.encode(
        [address, address],
        ["0x20b572be48527a770479744aec6fe5644f97678b", "0xcfeb832cd0705d719f72a8399ae6e83e6e63a1a1"]
    ) as HexString
}

async function waitForResponse(consumer: Contract, event: Event) {
    const [, data] = event.args!
    // Run Phat Function
    const result = execSync(`phat-fn run dist/index.js -a ${abiCoder()} somethingrandomlysecret`).toString()
    const json = JSON.parse(result)
    const action = ethers.utils.hexlify(ethers.utils.concat([new Uint8Array([0]), json.output]))
    // Make a response
    const tx = await consumer.rollupU256CondEq(
        // cond
        [],
        [],
        // updates
        [],
        [],
        // actions
        [action]
    )
    const receipt = await tx.wait()
    return receipt.events
}

describe("test_otp", function () {
    it("Push and receive message", async function () {
        // Deploy the contract
        const [deployer] = await ethers.getSigners()

        const OTPContract = await ethers.getContractFactory(BYTECODE__ABI.abi, BYTECODE__ABI.bytecode)
        const consumer = await OTPContract.deploy(deployer.address)

        // Make a request
        const tx = await consumer.getOTP()
        const receipt = await tx.wait()
        const reqEvents = receipt.events
        expect(reqEvents![0]).to.have.property("event", "MessageQueued")

        // Wait for Phat Function response
        const respEvents = await waitForResponse(consumer, reqEvents![0])

        // Check response data
        expect(respEvents[0]).to.have.property("event", "ResponseReceived")
        const [hash, receipient] = respEvents[0].args
        expect(receipient).to.equal("0x20b572be48527a770479744aec6fe5644f97678b")
    })
})
