import "@phala/pink-env"

type HexString = `0x${string}`

export default function (req: HexString, key: string) {
    const otp_api_endpoint = `https://phat-otp-demo-prod.up.railway.app/?key=${key}&payload=${req}`

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

    const body = JSON.parse(res.body.toString()) as {payload?: string; error?: string}
    if (res.statusCode == 200) {
        return body.payload
    }
    return body.error
}
