import { EventTable } from "@/components/Dashboard";
import { getMetrics } from "@/lib/get-metrics";

export const dynamic = "force-dynamic";

export default async function EventosPage() {
  const data = await getMetrics();
  return (
    <>
      <h1>Eventos</h1>
      <p className="lede">Bloqueios e mascaramentos, mais recentes primeiro.</p>
      {data.demo ? (
        <p className="banner" role="status">
          O proxy em :9000 não respondeu. Estes números são de demonstração.
        </p>
      ) : null}
      <EventTable events={data.recent_events} />
    </>
  );
}
