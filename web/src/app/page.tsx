import { Dashboard } from "@/components/Dashboard";
import { unavailableMetrics } from "@/lib/get-metrics";

export default function Page() {
  const initial = unavailableMetrics();
  return (
    <>
      <h1>Visão geral</h1>
      <p className="lede">O que o proxy viu. Atualiza sozinho a cada cinco segundos.</p>
      <Dashboard initial={initial} />
    </>
  );
}
