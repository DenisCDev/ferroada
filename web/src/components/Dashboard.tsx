"use client";

import { useEffect, useState } from "react";
import { eventLabel, formatInt, formatTime, totalBlocked } from "@/lib/labels";
import { metricsResultSchema, type FerroadaMetrics, type MetricsResult } from "@/lib/types";

type AuthState =
  | "loading"
  | "required"
  | "validating"
  | "authenticated"
  | "invalid"
  | "misconfigured"
  | "unavailable";

function shortPolicy(version: string | undefined): string {
  if (!version) return "—";
  const hex = version.replace(/^sha256:/, "");
  return hex.length > 12 ? hex.slice(0, 12) : hex;
}

function demoMessage(reason: MetricsResult["demo_reason"]): string {
  if (reason === "unauthorized") {
    return "O token do proxy está ausente ou incorreto. Confira FERROADA_TOKEN.";
  }
  if (reason === "invalid_response") {
    return "O proxy respondeu em um formato inesperado. Estes números são de demonstração.";
  }
  return "O proxy não está acessível. Estes números são de demonstração.";
}

function unavailableMessage(reason: MetricsResult["demo_reason"]): string {
  if (reason === "unauthorized") {
    return "O token do proxy está ausente ou incorreto. Confira FERROADA_TOKEN.";
  }
  if (reason === "invalid_response") {
    return "O proxy respondeu em um formato inesperado. Os totais estão a zero de propósito.";
  }
  return "O proxy não respondeu; os totais estão a zero de propósito.";
}

function useMetricsPolling(initial: MetricsResult) {
  const [data, setData] = useState(initial);
  const [pollError, setPollError] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [authState, setAuthState] = useState<AuthState>("loading");

  useEffect(() => {
    const stored = window.sessionStorage.getItem("ferroada-web-token");
    setToken(stored);
    setAuthState(stored ? "validating" : "required");
  }, []);

  useEffect(() => {
    if (!token) return;

    const refresh = () => {
      void fetch("/api/metrics", {
        cache: "no-store",
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(4_000),
      })
        .then(async (response) => {
          if (response.status === 401) {
            window.sessionStorage.removeItem("ferroada-web-token");
            setToken(null);
            setAuthState("invalid");
            setPollError(false);
            return null;
          }
          if (response.status === 503) {
            window.sessionStorage.removeItem("ferroada-web-token");
            setToken(null);
            setAuthState("misconfigured");
            setPollError(false);
            return null;
          }
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return metricsResultSchema.parse(await response.json());
        })
        .then((payload) => {
          if (!payload) return;
          setData(payload);
          setAuthState("authenticated");
          setPollError(false);
        })
        .catch(() => {
          setAuthState((current) => (current === "validating" ? "unavailable" : current));
          setPollError(true);
        });
    };

    refresh();
    const id = window.setInterval(refresh, 5_000);
    return () => window.clearInterval(id);
  }, [token]);

  const saveToken = (value: string) => {
    const normalized = value.trim();
    if (normalized.length < 16 || normalized.length > 512) return;
    window.sessionStorage.setItem("ferroada-web-token", normalized);
    setToken(normalized);
    setAuthState("validating");
    setPollError(false);
  };

  return { data, pollError, authState, saveToken };
}

function TokenPrompt({
  onSubmit,
  error,
}: {
  onSubmit: (token: string) => void;
  error?: string;
}) {
  const [value, setValue] = useState("");
  return (
    <form
      className="token-form"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(value);
      }}
    >
      <p className="banner" role="status">
        {error ?? "Informe o token do painel para carregar métricas e eventos reais."}
      </p>
      <label htmlFor="dashboard-token">Token do painel (mínimo de 16 caracteres)</label>
      <input
        id="dashboard-token"
        type="password"
        autoComplete="current-password"
        minLength={16}
        maxLength={512}
        required
        value={value}
        onChange={(event) => setValue(event.target.value)}
      />
      <button
        type="submit"
        disabled={value.trim().length < 16 || value.trim().length > 512}
      >
        Entrar
      </button>
    </form>
  );
}

function AuthBoundary({
  state,
  onSubmit,
}: {
  state: AuthState;
  onSubmit: (token: string) => void;
}) {
  if (state === "loading" || state === "validating") {
    return (
      <p className="banner" role="status">
        Validando o token do painel…
      </p>
    );
  }
  if (state === "required") return <TokenPrompt onSubmit={onSubmit} />;
  if (state === "invalid") {
    return <TokenPrompt onSubmit={onSubmit} error="Token rejeitado. Confira a credencial e tente novamente." />;
  }
  if (state === "misconfigured") {
    return (
      <p className="banner" role="alert">
        O servidor do painel não possui FERROADA_WEB_TOKEN válido. Configure a variável e reinicie o painel.
      </p>
    );
  }
  if (state === "unavailable") {
    return (
      <p className="banner" role="alert">
        Não foi possível validar o token agora. Uma nova tentativa será feita em cinco segundos.
      </p>
    );
  }
  return null;
}

function MetricsStatus({ data, pollError }: { data: MetricsResult; pollError: boolean }) {
  return (
    <>
      {data.demo ? (
        <p className="banner" role="status">
          {demoMessage(data.demo_reason)}
        </p>
      ) : null}
      {!data.demo && data.unavailable ? (
        <p className="banner" role="status">
          {unavailableMessage(data.demo_reason)}
        </p>
      ) : null}
      {pollError ? (
        <p className="banner" role="status">
          Não foi possível atualizar as métricas. Uma nova tentativa será feita em cinco segundos.
        </p>
      ) : null}
    </>
  );
}

export function Dashboard({ initial }: { initial: MetricsResult }) {
  const { data, pollError, authState, saveToken } = useMetricsPolling(initial);
  if (authState !== "authenticated") {
    return <AuthBoundary state={authState} onSubmit={saveToken} />;
  }

  const blocked = totalBlocked(data.blocked);
  const rate =
    data.requests_total === 0 ? 0 : (1 - blocked / Math.max(data.requests_total, blocked)) * 100;

  const rows = Object.entries(data.blocked)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <>
      <MetricsStatus data={data} pollError={pollError} />

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
        <div className="kpi">
          <dt>Política</dt>
          <dd className="mono">{shortPolicy(data.policy_version)}</dd>
        </div>
      </dl>

      <h2 className="section-title">Por tipo</h2>
      {rows.length === 0 ? (
        <p className="empty">
          {data.unavailable
            ? "Nenhum bloqueio a mostrar enquanto o proxy não responde."
            : "Nenhum bloqueio ainda. O proxy está escutando."}
        </p>
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
      <EventTable events={data.recent_events} unavailable={data.unavailable} />
    </>
  );
}

export function EventsPanel({ initial }: { initial: MetricsResult }) {
  const { data, pollError, authState, saveToken } = useMetricsPolling(initial);
  if (authState !== "authenticated") {
    return <AuthBoundary state={authState} onSubmit={saveToken} />;
  }
  return (
    <>
      <MetricsStatus data={data} pollError={pollError} />
      <EventTable events={data.recent_events} unavailable={data.unavailable} />
    </>
  );
}

export function EventTable({
  events,
  unavailable = false,
}: {
  events: FerroadaMetrics["recent_events"];
  unavailable?: boolean;
}) {
  if (events.length === 0) {
    return (
      <div className="table-wrap">
        <p className="empty">
          {unavailable
            ? "Nenhum evento a mostrar enquanto o proxy não responde."
            : "Nenhum evento de segurança recente."}
        </p>
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
