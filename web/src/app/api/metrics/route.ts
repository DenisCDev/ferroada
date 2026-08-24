import { getMetrics } from "@/lib/get-metrics";

export const dynamic = "force-dynamic";

export async function GET() {
  const data = await getMetrics();
  return Response.json(data);
}
