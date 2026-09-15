"use client";

import { useEffect, useState } from "react";
import { Icon } from "@/components/Icon";
import { eventAction, eventLabel, formatInt, formatTime, totalBlocked } from "@/lib/labels";
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

  const allowed = Math.max(data.requests_total - blocked, 0);
  const blockRate =
    data.requests_total === 0 ? 0 : (blocked / Math.max(data.requests_total, blocked)) * 100;
  const maxBlocked = Math.max(...rows.map(([, n]) => n), 1);

  return (
    <>
      <MetricsStatus data={data} pollError={pollError} />

      <section className="summary-grid" aria-label="Resumo da segurança">
        <article className="metric-card">
          <div className="metric-label">
            <span className="metric-icon steel">
              <span className="icon">
                <Icon name="arrows-down-up" />
              </span>
            </span>
            <h2>Requisições</h2>
          </div>
          <div className="metric-number">{formatInt(data.requests_total)}</div>
          <div className="metric-context">recebidas neste período</div>
          <div className="metric-footer">
            <span className="icon">
              <Icon name="pulse" />
            </span>
            Política <strong className="mono">{shortPolicy(data.policy_version)}</strong>
          </div>
        </article>
        <article className="metric-card">
          <div className="metric-label">
            <span className="metric-icon mint">
              <span className="icon">
                <Icon name="check" />
              </span>
            </span>
            <h2>Tráfego limpo</h2>
          </div>
          <div className="metric-number">
            {new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 1 }).format(rate)}
            <span>%</span>
          </div>
          <div className="metric-context">{formatInt(allowed)} requisições permitidas</div>
          <div className={data.unavailable || blocked > 0 ? "metric-footer" : "metric-footer good"}>
            <span className="icon">
              <Icon name="check-circle" />
            </span>
            {data.unavailable
              ? "Proxy indisponível"
              : blocked === 0
                ? "Nenhum bloqueio neste período"
                : "Requisições que passaram na inspeção"}
          </div>
        </article>
        <article className="metric-card">
          <div className="metric-label">
            <span className="metric-icon gold">
              <span className="icon">
                <Icon name="prohibit" />
              </span>
            </span>
            <h2>Ameaças bloqueadas</h2>
          </div>
          <div className="metric-number">{formatInt(blocked)}</div>
          <div className="metric-context">interceptadas antes da aplicação</div>
          <div className="metric-footer">
            <span className="small-dot amber" />
            <strong>
              {new Intl.NumberFormat("pt-BR", { maximumFractionDigits: 2 }).format(blockRate)}%
            </strong>{" "}
            do tráfego recebido
          </div>
        </article>
        <article className="metric-card">
          <div className="metric-label">
            <span className="metric-icon rose">
              <span className="icon">
                <Icon name="fingerprint" />
              </span>
            </span>
            <h2>Eventos de DLP</h2>
          </div>
          <div className="metric-number">
            {formatInt(data.dlp.cpf_masked + data.dlp.tokens_masked)}
          </div>
          <div className="metric-context">dados sensíveis mascarados</div>
          <div className="metric-footer">
            <span className="icon">
              <Icon name="lock-key" />
            </span>
            Políticas de CPF e token
          </div>
        </article>
      </section>

      <section aria-labelledby="threat-title">
        <div className="section-heading">
          <div>
            <h2 id="threat-title">O que foi bloqueado</h2>
            <span className="subtle-count">
              {rows.length === 0 ? "nenhum tipo" : `${formatInt(rows.length)} tipos`}
            </span>
          </div>
        </div>
        {rows.length === 0 ? (
          <p className="empty">
            {data.unavailable
              ? "Nenhum bloqueio a mostrar enquanto o proxy não responde."
              : "Nenhum bloqueio ainda. O proxy está escutando."}
          </p>
        ) : (
          <ul className="threat-list">
            {rows.map(([k, n]) => (
              <li className="threat-item" key={k}>
                <span className="threat-name">{eventLabel(k)}</span>
                <div className="threat-bar" aria-hidden="true">
                  <span style={{ width: `${(n / maxBlocked) * 100}%` }} />
                </div>
                <span className="threat-count">{formatInt(n)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="events-section" aria-labelledby="events-title">
        <div className="section-heading events-heading">
          <div>
            <h2 id="events-title">Eventos recentes</h2>
            <span className="live-label">
              <span
                className={
                  pollError || data.unavailable ? "small-dot amber" : "small-dot green"
                }
              />
              {pollError
                ? "Falha na atualização"
                : data.unavailable
                  ? "Proxy indisponível"
                  : "Atualiza a cada 5 s"}
            </span>
          </div>
        </div>
        <EventTable events={data.recent_events} unavailable={data.unavailable} />
      </section>
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
      <section className="events-section" aria-labelledby="events-title">
        <div className="section-heading events-heading">
          <div>
            <h2 id="events-title">Eventos recentes</h2>
            <span className="live-label">
              <span
                className={
                  pollError || data.unavailable ? "small-dot amber" : "small-dot green"
                }
              />
              {pollError
                ? "Falha na atualização"
                : data.unavailable
                  ? "Proxy indisponível"
                  : "Atualiza a cada 5 s"}
            </span>
          </div>
        </div>
        <EventTable events={data.recent_events} unavailable={data.unavailable} />
      </section>
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
      <div className="table-scroll">
        <p className="empty">
          {unavailable
            ? "Nenhum evento a mostrar enquanto o proxy não responde."
            : "Nenhum evento de segurança recente."}
        </p>
      </div>
    );
  }

  return (
    <div className="table-scroll">
      <table className="events-table">
        <thead>
          <tr>
            <th className="time-col">Horário</th>
            <th>Evento</th>
            <th className="origin-col">Origem</th>
            <th>Ação</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => {
            const action = eventAction(e.event_type);
            return (
              <tr key={`${e.timestamp}-${e.client_ip}-${i}`}>
                <td className="time-cell">{formatTime(e.timestamp)}</td>
                <td>
                  <span className="event-name">{eventLabel(e.event_type)}</span>
                  <span className="event-route">{e.uri}</span>
                </td>
                <td>
                  <span className="origin-ip">{e.client_ip}</span>
                </td>
                <td>
                  <span className={`status-badge ${action.kind}`}>{action.label}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
