// pages/api/ig/webhook.ts
import type { NextApiRequest, NextApiResponse } from 'next'
import crypto from 'crypto'
import getRawBody from 'raw-body'
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";

const ses = new SESClient({
    region: process.env.AWS_REGION ?? "us-east-1",
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,       // Vercel環境変数に設定
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,// Vercel環境変数に設定
    },
});

export const config = {
    api: { bodyParser: false },
}

const VERIFY_TOKEN = process.env.META_VERIFY_TOKEN!
const APP_SECRET = process.env.META_APP_SECRET!
const FORWARD_TO = process.env.FORWARD_TO!

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
            if (!verifySignature(raw, headerSig, APP_SECRET)) {
                return res.status(401).send('Invalid signature')
            }

            const payload = JSON.parse(raw.toString('utf-8'))

            // Instagram Messagingのpayloadは "entry" 配列配下にメッセージが入る（Messengerプラットフォーム準拠）
            // 代表的には entry[].messaging[].message.text / sender.id 等。実際はパターンあり。
            const items: Array<{ senderId: string; text: string }> = []
            for (const entry of payload.entry ?? []) {
                for (const m of entry.messaging ?? []) {
                    const senderId = m?.sender?.id
                    const text = m?.message?.text
                    if (senderId && senderId !== "17841400653016045" &&typeof text === 'string') {
                        items.push({ senderId, text })
                    }
                }
            }

            if (items.length > 0) {
                await sendMailViaSES(FORWARD_TO, items)
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

export async function sendMailViaSES(
    to: string,
    items: Array<{ senderId: string; text: string }>
) {
    const from = 'インスタDM通知Bot <instagram_dm@tai.tokyo>'; // ← Verify必須
    const subject = `Instagram DM (${items.length} new)`;
    const text = items.map(i => `from=${i.senderId}\n\n${i.text}`).join('\n\n---\n\n');

    const command = new SendEmailCommand({
        Source: from,
        Destination: { ToAddresses: [to] },
        Message: {
        Subject: { Data: subject, Charset: "UTF-8" },
        Body: { Text: { Data: text, Charset: "UTF-8" } },
        },
    });

    try {
        const data = await ses.send(command);
        console.log("Email sent successfully", { messageId: data.MessageId });
        console.log(items.map(i => `from=${i.senderId}\n\n${i.text}`).join('\n\n---\n\n'))
    } catch (e: any) {
        console.error("Failed to send email via SES", e);
        throw new Error(`SES send failed: ${e?.message ?? e}`);
    }
}

function verifySignature(rawBody: Buffer, headerSig: string | undefined, appSecret: string) {
    if (!headerSig) return false
    const [scheme, provided] = headerSig.split('=')
    if (scheme !== 'sha256' || !provided) return false
    const expected = crypto.createHmac('sha256', appSecret).update(rawBody).digest('hex')
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))
}
