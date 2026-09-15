"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { Icon } from "@/components/Icon";

const LINKS = [
  { href: "/", label: "Visão geral", icon: "squares-four" as const },
  { href: "/eventos", label: "Eventos e logs", icon: "list-bullets" as const },
];

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const [navOpen, setNavOpen] = useState(false);
  const current = LINKS.find((link) => link.href === path)?.label ?? "Visão geral";

  useEffect(() => {
    setNavOpen(false);
  }, [path]);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navOpen]);

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        Pular para o conteúdo
      </a>
      <aside className="utility-rail" aria-label="Atalhos do workspace">
        <Link href="/" className="rail-brand" aria-label="Ferroada: início">
          <svg viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <path
              d="M7 25V7h18M7 16h15M16 7v18"
              stroke="currentColor"
              strokeWidth="3.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </Link>
        <div className="rail-divider" />
        {LINKS.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className={path === link.href ? "rail-button active" : "rail-button"}
            aria-label={link.label}
            title={link.label}
            aria-current={path === link.href ? "page" : undefined}
          >
            <span className="icon">
              <Icon name={link.icon} />
            </span>
          </Link>
        ))}
        <div className="rail-spacer" />
        <span className="rail-user" aria-hidden="true">
          F
        </span>
      </aside>

      {navOpen ? (
        <button
          type="button"
          className="sidebar-scrim"
          tabIndex={-1}
          aria-hidden="true"
          onClick={() => setNavOpen(false)}
        />
      ) : null}

      <aside className={navOpen ? "sidebar open" : "sidebar"} id="sidebar" aria-label="Navegação principal">
        <div className="brand-line">
          <span className="brand-name">
            Ferroada<span className="brand-period">.</span>
          </span>
          <span className="brand-plan">WORKSPACE</span>
          <button
            type="button"
            className="icon-button mobile-close"
            aria-label="Fechar navegação"
            onClick={() => setNavOpen(false)}
          >
            <span className="icon">
              <Icon name="x" />
            </span>
          </button>
        </div>
        <div className="workspace-switch">
          <span className="workspace-avatar">
            <span className="icon">
              <Icon name="stack" />
            </span>
          </span>
          <span>
            <strong>Ambiente principal</strong>
            <small>loopback · painel Next</small>
          </span>
        </div>
        <nav aria-label="Principal">
          <div className="nav-section-label">MONITORAMENTO</div>
          {LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={path === link.href ? "nav-item active" : "nav-item"}
              aria-current={path === link.href ? "page" : undefined}
            >
              <span className="icon">
                <Icon name={link.icon} />
              </span>
              <span>{link.label}</span>
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-health">
            <span className="health-orb" aria-hidden="true" />
            <div>
              <strong>Painel local</strong>
              <span>métricas a cada 5 s</span>
            </div>
          </div>
        </div>
      </aside>

      <div className="main-surface">
        <header className="topbar">
          <button
            type="button"
            className="icon-button mobile-menu"
            aria-label="Abrir navegação"
            aria-expanded={navOpen}
            aria-controls="sidebar"
            onClick={() => setNavOpen(true)}
          >
            <span className="icon">
              <Icon name="list" />
            </span>
          </button>
          <div className="coverage-icon">
            <span className="icon">
              <Icon name="shield-check" />
            </span>
          </div>
          <div className="coverage-copy">
            <div>
              Proteção do ambiente <span>proxy de origem</span>
            </div>
            <div className="coverage-track" aria-hidden="true">
              <i />
            </div>
          </div>
          <div className="topbar-right">
            <span className="account-mark" aria-hidden="true">
              FR
            </span>
          </div>
        </header>
        <div className="breadcrumb-row">
          <div className="breadcrumbs">
            <span>Workspace</span>
            <span>/</span>
            <span>Ambiente principal</span>
            <span>/</span>
            <strong>{current}</strong>
          </div>
        </div>
        <main className="content" id="main-content" tabIndex={-1}>
          {children}
        </main>
        <footer className="system-footer">
          <div>
            <span className="icon">
              <Icon name="hard-drives" />
            </span>
            <span>
              Painel Next <strong>web/</strong>
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
