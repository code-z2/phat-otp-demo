import "@phala/pink-env"
import {Coders} from "@phala/ethers"
import {config} from "dotenv"

config()

type HexString = `0x${string}`

const bytes32 = new Coders.FixedBytesCoder(32, "bytes32")
const bytes = new Coders.BytesCoder("bytes")
const address = new Coders.AddressCoder("address")
const uint8 = new Coders.NumberCoder(8, false, "uint8")

function decodeAbi(data: HexString) {
    return Coders.decode([address, address], data)
}
function encodeAbi(otpHash: string, recipient: string, code: number, signature: string): HexString {
    return Coders.encode([bytes32, address, uint8, bytes], [otpHash, recipient, code, signature]) as HexString
}

export default function (req: HexString) {
    let recipient, sender
    try {
        ;[recipient, sender] = decodeAbi(req)
    } catch (error) {
        return encodeAbi("0x0", "0x0", 1, "0x0")
    }

    const otp_api_endpoint = `http://localhost:3001/?key=${process.env.OTP_API_KEY}&recipient=${recipient}&sender=${sender}`

    let headers = {
        "Content-Type": "application/json",
        "User-Agent": "phat-contract",
    }

    const res = pink.httpRequest({
        url: otp_api_endpoint,
        method: "GET",
        headers,
        returnTextBody: true,
    })

    if (res.statusCode == 200) {
        const body = JSON.parse(res.body as string) as {otp: string; recipient: string; signature: string}
        console.info(body)
        return encodeAbi(body.otp, body.recipient, 0, body.signature)
    }
    return encodeAbi("0x0", "0x0", 1, "0x0")
}
