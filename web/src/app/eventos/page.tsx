import { EventsPanel } from "@/components/Dashboard";
import { demoMetrics } from "@/lib/demo";

export default function EventosPage() {
  const data = { ...demoMetrics(), demo: true as const, demo_reason: "unavailable" as const };
  return (
    <>
      <h1>Eventos</h1>
      <p className="lede">Eventos de segurança e observações, mais recentes primeiro.</p>
      <EventsPanel initial={data} />
    </>
  );
}
