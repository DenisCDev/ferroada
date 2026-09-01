import { Dashboard } from "@/components/Dashboard";
import { demoMetrics } from "@/lib/demo";

export default function Page() {
  const initial = { ...demoMetrics(), demo: true as const, demo_reason: "unavailable" as const };
  return (
    <>
      <h1>Visão geral</h1>
      <p className="lede">O que o proxy viu. Atualiza sozinho a cada cinco segundos.</p>
      <Dashboard initial={initial} />
    </>
  );
}
