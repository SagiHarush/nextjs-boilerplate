import crypto from "crypto";

export const runtime = "nodejs";

function verifySlackSignature(
  rawBody: string,
  timestamp: string,
  signature: string
) {
  const signingSecret = process.env.SLACK_SIGNING_SECRET!;

  // Reject replayed requests older than 5 minutes
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 60 * 5) return false;

  const base = `v0:${timestamp}:${rawBody}`;
  const expected =
    "v0=" +
    crypto
      .createHmac("sha256", signingSecret)
      .update(base)
      .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signature)
  );
}

async function slackGet(method: string, params: Record<string, string>) {
  const url = new URL(`https://slack.com/api/${method}`);

  Object.entries(params).forEach(([key, value]) =>
    url.searchParams.set(key, value)
  );

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}`,
    },
  });

  return response.json();
}

export async function POST(req: Request) {
  const rawBody = await req.text();

  const timestamp = req.headers.get("x-slack-request-timestamp") ?? "";
  const signature = req.headers.get("x-slack-signature") ?? "";

  if (
    !timestamp ||
    !signature ||
    !verifySlackSignature(rawBody, timestamp, signature)
  ) {
    return new Response("Invalid Slack signature", { status: 401 });
  }

  const body = JSON.parse(rawBody);

  // Slack URL verification
  if (body.type === "url_verification") {
    return Response.json({ challenge: body.challenge });
  }

  if (body.type !== "event_callback") {
    return new Response("Ignored", { status: 200 });
  }

  const event = body.event;

  // Only regular public-channel messages
  if (event.type !== "message") {
    return new Response("Ignored", { status: 200 });
  }

  // Ignore bot/system/edit events
  if (event.bot_id || event.subtype) {
    return new Response("Ignored", { status: 200 });
  }

  // Only ingest our Product Discovery channel
  if (event.channel !== process.env.SLACK_FEEDBACK_CHANNEL_ID) {
    return new Response("Ignored", { status: 200 });
  }

  const [userResult, permalinkResult] = await Promise.all([
    slackGet("users.info", { user: event.user }),
    slackGet("chat.getPermalink", {
      channel: event.channel,
      message_ts: event.ts,
    }),
  ]);

  const userName =
    userResult?.user?.profile?.display_name ||
    userResult?.user?.real_name ||
    event.user;

  const portPayload = {
    channel_id: event.channel,
    ts: event.ts,
    user: event.user,
    user_name: userName,
    text: event.text,
    permalink: permalinkResult?.permalink ?? null,
    customer: null,
  };

  const portResponse = await fetch(
    process.env.PORT_SLACK_WEBHOOK_URL!,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(portPayload),
    }
  );

  if (!portResponse.ok) {
    console.error(
      "Port webhook failed:",
      portResponse.status,
      await portResponse.text()
    );

    return new Response("Port webhook failed", { status: 500 });
  }

  return new Response("OK", { status: 200 });
}