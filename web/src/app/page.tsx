import { Dashboard } from "@/components/Dashboard";
import { unavailableMetrics } from "@/lib/get-metrics";

export default function Page() {
  const initial = unavailableMetrics();
  return (
    <>
      <section className="page-heading">
        <div>
          <h1>Visão geral</h1>
          <p>O que o proxy viu. Atualiza sozinho a cada cinco segundos.</p>
        </div>
      </section>
      <Dashboard initial={initial} />
    </>
  );
}
