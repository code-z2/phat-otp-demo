import express from "express"
import crypto from "crypto"
import cors from "cors"
import {Wallet, constants, utils} from "ethers"
import {Client} from "@xmtp/xmtp-js"
import {config} from "dotenv"
import {arrayify, defaultAbiCoder, isAddress, randomBytes} from "ethers/lib/utils"

config()

const app = express()
const port = process.env.PORT || 3000
const env = (process.env.ENV as "local" | "dev" | "production" | undefined) || "dev"

const apiKey = process.env.API_KEY
const privKey = env === "production" ? process.env.PRIV_KEY : process.env.LOCAL_PRIV_KEY
const wallet = privKey ? new Wallet(privKey) : Wallet.createRandom()

// Middleware to parse JSON requests
app.use(express.json())

// Enable CORS for all routes
app.use(cors()) // Add this line to enable CORS

let xmtp: Client

// Generate a random 6-digit OTP
function generateOTP(): string {
    return Math.floor(100000 + Math.random() * 900000).toString()
}

function formartAddress(address: string): string {
    return address.startsWith("0x") && address.length === 42
        ? address.substring(0, 6) + "..." + address.substring(address.length - 4)
        : address
}

function encodeError(error: string): string {
    return defaultAbiCoder.encode(
        ["bytes32", "uint256", "address", "bytes"],
        [randomBytes(32), 1, constants.AddressZero, arrayify(utils.solidityKeccak256(["string"], [error]))]
    )
}

// Create a route to generate and return OTP details
// Using the default route for simplicity
app.get("/", async (req, res) => {
    const payload = req.query.payload as string | undefined // Get the wallet address from the request body
    const key = req.query.key as string | undefined

    if (!payload) {
        return res.status(400).json({error: encodeError("Invalid Payload")})
    }
    if (!key || key !== apiKey) {
        return res.status(401).json({error: encodeError("Unauthorized")})
    }
    const [recipient, sender] = defaultAbiCoder.decode(["address", "address"], payload)

    if (
        !isAddress(recipient) ||
        !isAddress(sender) ||
        recipient == constants.AddressZero ||
        sender == constants.AddressZero
    ) {
        return res.status(400).json({error: encodeError("Address or Recipient invalid")})
    }

    const canMessage = await xmtp.canMessage(recipient)
    if (!canMessage) {
        return res.status(403).json({error: encodeError("Unable to message this recipient")})
    }

    const conversation = await xmtp.conversations.newConversation(recipient)

    // Generate OTP and timestamp
    const otp = generateOTP()
    const message = `your ${formartAddress(
        sender || "UNKNOWN_CONTRACT"
    )} verification code is: ${otp}. Don't share this code with anyone; confirm that you initiated it from ${formartAddress(
        sender || "UNKNOWN_CONTRACT"
    )}!`

    await conversation.send(message)

    // Compute SHA-256 hash of the OTP
    const otpHash = utils.solidityKeccak256(["string"], [crypto.createHash("sha256").update(otp).digest("hex")])
    // generates a valid signature to be used to verify the message
    const signature = await wallet.signMessage(arrayify(otpHash))

    // production logs
    if (env === "production") {
        console.log(`request: ${req.ip}, otpHash: ${otpHash}, signature: ${signature}`)
    }

    // Return OTP details as JSON
    res.json({
        payload: utils.solidityPack(["bytes32", "uint256", "address", "bytes"], [otpHash, 0, recipient, signature]),
    })
})

app.listen(port, async () => {
    xmtp = await Client.create(wallet, {env})
    console.log(`Server is running on port ${port}`)
})
