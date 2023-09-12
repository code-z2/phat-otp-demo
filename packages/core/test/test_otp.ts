import {expect} from "chai"
import {type Contract, type Event} from "ethers"
import {ethers} from "hardhat"
import {execSync} from "child_process"
import {Coders} from "@phala/ethers"

// compile contracts to generate this file
import JSON_INTERFACE from "../../contracts/out/OTP.sol/OTP.json"

type HexString = `0x${string}`

const address = new Coders.AddressCoder("address")

const test_receiver = "0x20b572be48527a770479744aec6fe5644f97678b"
const test_sender = "0xcfeb832cd0705d719f72a8399ae6e83e6e63a1a1"

function abiCoder() {
    const payload = Coders.encode([address, address], [test_receiver, test_sender]) as HexString
    return payload
}

async function waitForResponse(consumer: Contract, event: Event) {
    const [, data] = event.args!
    // Run Phat Function
    const result = execSync(`phat-fn run dist/index.js -a ${abiCoder()} somethingrandomlysecret`)
    const json = JSON.parse(result.toString())
    const action = ethers.utils.hexlify(ethers.utils.concat([new Uint8Array([0]), json.output]))
    console.log("action: ", action)

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

        const OTPContract = await ethers.getContractFactory(JSON_INTERFACE.abi, JSON_INTERFACE.bytecode.object)
        const consumer = await OTPContract.deploy(deployer.address)

        // Make a request
        const tx = await consumer.getOTP()
        const receipt = await tx.wait()
        const reqEvents = receipt.events
        expect(reqEvents![0]).to.have.property("event", "MessageQueued")

        // Wait for Phat Function response
        const respEvents = await waitForResponse(consumer, reqEvents![0])

        // Check response data
        expect(respEvents[0]).to.have.property("event", "OTPReceived")
        const [hash, recipient] = respEvents[0].args
        expect(recipient.toLowerCase()).to.equal(test_receiver.toLowerCase())
        const record = await consumer.otpRecords(recipient)
        expect(record).to.have.property("otpHash", hash)
    })
})
