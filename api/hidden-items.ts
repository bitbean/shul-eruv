import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";

const COOKIE_NAME = "__Secure-eruv-hidden-items";
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_BODY_BYTES = 1024;

const shulsSchema = z.array(z.object({
  name: z.string().trim().min(1),
  position: z.tuple([
    z.number().min(-90).max(90),
    z.number().min(-180).max(180),
  ]),
})).min(1);

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function passwordHash(value: string) {
  return createHash("sha256").update(value).digest();
}

async function readPassword(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      request.resume();
      return undefined;
    }
    chunks.push(chunk);
  }

  const body = parseJson(Buffer.concat(chunks).toString("utf8"));
  if (body && typeof body === "object" && "password" in body && typeof body.password === "string") {
    return body.password;
  }
}

export function handleHiddenItems(request: IncomingMessage, response: ServerResponse, env: NodeJS.ProcessEnv) {
  const send = (status: number, body: object) => {
    response.writeHead(status, {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(JSON.stringify(body));
  };

  if (request.method !== "GET" && request.method !== "POST") {
    response.setHeader("Allow", "GET, POST");
    return send(405, { error: "Method not allowed." });
  }

  const password = env.SHUL_MAP_PASSWORD;
  const signingKey = env.SHUL_MAP_SESSION_KEY;
  if (!password || password.length < 16 || password.length > 128 || !signingKey || signingKey.length < 32 || !env.SHUL_MAP_ITEMS) {
    return send(503, { error: "Shul access is unavailable." });
  }

  const expectedPassword = passwordHash(password);
  // Bind the signature to the current password so rotating it also revokes existing sessions.
  const sign = (expiresAt: number) => createHmac("sha256", signingKey)
    .update(expectedPassword)
    .update(String(expiresAt))
    .digest();

  const sendShuls = (expiresAt: number, newSession = false) => {
    const items = shulsSchema.safeParse(parseJson(env.SHUL_MAP_ITEMS ?? ""));
    if (!items.success) return send(503, { error: "Shul access is unavailable." });

    if (newSession) {
      const token = `${expiresAt}.${sign(expiresAt).toString("base64url")}`;
      response.setHeader("Set-Cookie", `${COOKIE_NAME}=${token}; Path=/api/hidden-items; Max-Age=${SESSION_SECONDS}; HttpOnly; Secure; SameSite=Strict`);
    }
    return send(200, { items: items.data, expiresAt });
  };

  if (request.method === "GET") {
    const cookie = request.headers.cookie?.split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${COOKIE_NAME}=`))
      ?.slice(COOKIE_NAME.length + 1);
    const session = cookie?.match(/^(\d{13})\.([\w-]{43})$/);
    if (session) {
      const expiresAt = Number(session[1]);
      const signature = Buffer.from(session[2], "base64url");
      if (expiresAt > Date.now() && timingSafeEqual(signature, sign(expiresAt))) {
        return sendShuls(expiresAt);
      }
    }
    return send(401, { error: "Password required." });
  }

  // Requiring JSON prevents cross-origin forms from creating a session.
  if (request.headers["content-type"]?.split(";", 1)[0].trim() !== "application/json") {
    return send(415, { error: "Expected JSON." });
  }

  return readPassword(request).then((submittedPassword) => {
    if (!submittedPassword || !timingSafeEqual(passwordHash(submittedPassword), expectedPassword)) {
      return send(401, { error: "Incorrect password." });
    }
    return sendShuls(Date.now() + SESSION_SECONDS * 1000, true);
  }, () => send(400, { error: "Invalid request." }));
}

export default function handler(request: IncomingMessage, response: ServerResponse) {
  return handleHiddenItems(request, response, process.env);
}
