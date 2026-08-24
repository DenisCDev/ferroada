"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

const LINKS = [
  { href: "/", label: "Visão geral" },
  { href: "/eventos", label: "Eventos" },
];

export function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();

  return (
    <div className="shell">
      <aside className="nav">
        <div className="brand">
          Ferroada
          <span>proxy de segurança</span>
        </div>
        <nav className="links" aria-label="Principal">
          {LINKS.map((l) => (
            <Link key={l.href} href={l.href} className={path === l.href ? "active" : undefined}>
              {l.label}
            </Link>
          ))}
        </nav>
      </aside>
      <div className="main">{children}</div>
    </div>
  );
}
