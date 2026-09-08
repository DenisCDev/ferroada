import { EventsPanel } from "@/components/Dashboard";
import { unavailableMetrics } from "@/lib/get-metrics";

export default function EventosPage() {
  const data = unavailableMetrics();
  return (
    <>
      <h1>Eventos</h1>
      <p className="lede">Eventos de segurança e observações, mais recentes primeiro.</p>
      <EventsPanel initial={data} />
    </>
  );
}
