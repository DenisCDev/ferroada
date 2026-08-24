"use client";

import { useEffect, useState } from "react";
import { eventLabel, formatInt, formatTime, totalBlocked } from "@/lib/labels";
import type { FerroadaMetrics } from "@/lib/types";

type Payload = FerroadaMetrics & { demo?: boolean };

export function Dashboard({ initial }: { initial: Payload }) {
  const [data, setData] = useState(initial);

  useEffect(() => {
    const id = window.setInterval(() => {
      void fetch("/api/metrics", { cache: "no-store", signal: AbortSignal.timeout(4_000) })
        .then((r) => r.json())
        .then((json: Payload) => setData(json))
        .catch(() => undefined);
    }, 5_000);
    return () => window.clearInterval(id);
  }, []);

  const blocked = totalBlocked(data.blocked);
  const rate =
    data.requests_total === 0 ? 0 : (1 - blocked / Math.max(data.requests_total, blocked)) * 100;

  const rows = Object.entries(data.blocked)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <>
      {data.demo ? (
        <p className="banner" role="status">
          O proxy em :9000 não respondeu. Estes números são de demonstração.
        </p>
      ) : null}

      <dl className="kpis">
        <div className="kpi">
          <dt>Requisições</dt>
          <dd>{formatInt(data.requests_total)}</dd>
        </div>
        <div className="kpi">
          <dt>Bloqueios</dt>
          <dd>{formatInt(blocked)}</dd>
        </div>
        <div className="kpi">
          <dt>Tráfego limpo</dt>
          <dd>
            {new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 1 }).format(rate)}%
          </dd>
        </div>
        <div className="kpi">
          <dt>DLP</dt>
          <dd>{formatInt(data.dlp.cpf_masked + data.dlp.tokens_masked)}</dd>
        </div>
      </dl>

      <h2 className="section-title">Por tipo</h2>
      {rows.length === 0 ? (
        <p className="empty">Nenhum bloqueio ainda. O proxy está escutando.</p>
      ) : (
        <ul className="breakdown">
          {rows.map(([k, n]) => (
            <li key={k}>
              <span>{eventLabel(k)}</span>
              <span className="count">{formatInt(n)}</span>
            </li>
          ))}
        </ul>
      )}

      <h2 className="section-title">Últimos eventos</h2>
      <EventTable events={data.recent_events} />
    </>
  );
}

export function EventTable({ events }: { events: FerroadaMetrics["recent_events"] }) {
  if (events.length === 0) {
    return (
      <div className="table-wrap">
        <p className="empty">Nenhum evento recente. Quando o WAF bloquear, aparece aqui.</p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Hora</th>
            <th>Tipo</th>
            <th>IP</th>
            <th>URI</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={`${e.timestamp}-${e.client_ip}-${i}`}>
              <td className="mono">{formatTime(e.timestamp)}</td>
              <td>{eventLabel(e.event_type)}</td>
              <td className="mono">{e.client_ip}</td>
              <td className="mono">{e.uri}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
