import { createHash, timingSafeEqual } from "node:crypto";
import { getMetrics } from "@/lib/get-metrics";
import { z } from "zod";

export const dynamic = "force-dynamic";

const tokenSchema = z.string().trim().min(16).max(512);

function digest(value: string): Buffer {
  return createHash("sha256").update(value).digest();
}

export async function GET(request: Request) {
  const expected = tokenSchema.safeParse(process.env.FERROADA_WEB_TOKEN);
  if (!expected.success) {
    return Response.json(
      { error: "FERROADA_WEB_TOKEN não está configurado com pelo menos 16 caracteres." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const authorization = request.headers.get("authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  if (!timingSafeEqual(digest(expected.data), digest(supplied))) {
    return Response.json(
      { error: "Não autorizado." },
      {
        status: 401,
        headers: { "Cache-Control": "no-store", "WWW-Authenticate": "Bearer" },
      },
    );
  }

  const data = await getMetrics();
  return Response.json(data, { headers: { "Cache-Control": "no-store" } });
}
