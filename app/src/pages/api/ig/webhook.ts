// pages/api/ig/webhook.ts
import type { NextApiRequest, NextApiResponse } from 'next'
import crypto from 'crypto'
import getRawBody from 'raw-body'

export const config = {
    api: { bodyParser: false },
}

const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN!
const APP_SECRET = process.env.META_APP_SECRET!
const FORWARD_TO = process.env.FORWARD_TO!
const RESEND_API_KEY = process.env.RESEND_API_KEY!

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method === 'GET') {
        const mode = req.query['hub.mode']
        const token = req.query['hub.verify_token']
        const challenge = req.query['hub.challenge']
        if (mode === 'subscribe' && token === VERIFY_TOKEN && typeof challenge === 'string') {
            return res.status(200).send(challenge)
        }
        return res.status(403).send('Forbidden')
    }

    if (req.method === 'POST') {
        try {
            const raw = await getRawBody(req)
            const headerSig = req.headers['x-hub-signature-256'] as string | undefined
            console.log('Received POST /api/ig/webhook', { raw: raw.toString('utf-8'), headerSig })
            if (!verifySignature(raw, headerSig, APP_SECRET)) {
                console.warn('Invalid signature')
                return res.status(401).send('Invalid signature')
            }

            const payload = JSON.parse(raw.toString('utf-8'))

            // Instagram Messagingのpayloadは "entry" 配列配下にメッセージが入る（Messengerプラットフォーム準拠）
            // 代表的には entry[].messaging[].message.text / sender.id 等。実際はパターンあり。
            const items: Array<{ senderId: string; text: string }> = []
            for (const entry of payload.entry ?? []) {
                for (const m of entry.messaging ?? []) {
                    const text = m?.message?.text
                    const senderId = m?.sender?.id
                    if (senderId && typeof text === 'string') {
                        items.push({ senderId, text })
                    }
                }
            }

            if (items.length > 0) {
                await sendMailViaResend(RESEND_API_KEY, FORWARD_TO, items)
            }

            return res.status(200).send('OK')
        } catch (e) {
            console.error(e)
            return res.status(500).send('Server error')
        }
    }

    res.setHeader('Allow', 'GET,POST')
    return res.status(405).end('Method Not Allowed')
}

function verifySignature(rawBody: Buffer, headerSig: string | undefined, appSecret: string) {
    if (!headerSig) {
        return false
    }
    const [scheme, provided] = headerSig.split('=')
    if (scheme !== 'sha256' || !provided) {
        return false
    }
    const expected = crypto.createHmac('sha256', appSecret).update(rawBody).digest('hex')
    console.log({ provided, expected })
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))
}

async function sendMailViaResend(apiKey: string, to: string, items: Array<{ senderId: string; text: string }>) {
    const body = {
        from: 'instagram-dm@yourdomain.example',
        to: [to],
        subject: `Instagram DM (${items.length} new)`,
        text: items.map(i => `from=${i.senderId}\n${i.text}`).join('\n\n---\n\n'),
    }
    await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    })
}
