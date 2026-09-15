import { EventsPanel } from "@/components/Dashboard";
import { unavailableMetrics } from "@/lib/get-metrics";

export default function EventosPage() {
  const data = unavailableMetrics();
  return (
    <>
      <section className="page-heading">
        <div>
          <h1>Eventos</h1>
          <p>Eventos de segurança e observações, mais recentes primeiro.</p>
        </div>
      </section>
      <EventsPanel initial={data} />
    </>
  );
}
