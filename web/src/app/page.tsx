import { Dashboard } from "@/components/Dashboard";
import { getMetrics } from "@/lib/get-metrics";

export const dynamic = "force-dynamic";

export default async function Page() {
  const initial = await getMetrics();
  return (
    <>
      <h1>Visão geral</h1>
      <p className="lede">O que o proxy viu. Atualiza sozinho a cada cinco segundos.</p>
      <Dashboard initial={initial} />
    </>
  );
}
