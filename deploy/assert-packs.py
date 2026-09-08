"""Fail-closed snapshot for topology packs (PR 1). No network."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOPO = ROOT / "topologies"
CIDRS = ROOT / "cidrs"
FORBIDDEN_ANY = (
    "DLP_ACTION",
    "ORIGIN_SECRET",
    "FERROADA_PRODUCTION",
    "FERROADA_ALLOW_DEMO",
    "PROXY_LISTEN",
    "location /supabase",
)
MODES = (
    "vps-site",
    "vps-api",
    "vps-supabase-selfhost",
    "vps-supabase-cloud",
    "vps-full",
    "hostinger-origin",
    "vercel-origin",
    "cdn-edge",
)


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    errors: list[str] = []
    for name in ("cloudflare.txt", "fastly.txt", "akamai.txt"):
        text = (CIDRS / name).read_text(encoding="utf-8")
        if "https://" not in text:
            errors.append(f"{name}: falta URL oficial no cabeçalho")
        if "2026-09-08" not in text:
            errors.append(f"{name}: falta data do snapshot")

    for mode in MODES:
        d = TOPO / mode
        if not d.is_dir():
            errors.append(f"falta modo {mode}")
            continue
        for path in d.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            rel = path.relative_to(ROOT)
            for needle in FORBIDDEN_ANY:
                if needle in text:
                    errors.append(f"{rel}: contém {needle!r}")
            if '"9000:9000"' in text or "- 9000:9000" in text:
                errors.append(f"{rel}: publica 9000 em todas as interfaces")
            if "header_up X-Forwarded-For {http.request.header.X-Forwarded-For}" in text:
                errors.append(f"{rel}: Caddy reescreve XFF com o valor do cliente")
            if "internal: true" in text:
                errors.append(f"{rel}: overlay origin sem egresso")
            if "PROXY_PROTOCOL" in text:
                errors.append(f"{rel}: contém PROXY_PROTOCOL")
            if path.name == "ferroada.service":
                if "Listen=80" in text or "Listen=:80" in text:
                    errors.append(f"{rel}: unit promete :80")
                if "AmbientCapabilities=CAP_NET_BIND_SERVICE" in text:
                    errors.append(f"{rel}: cap sem knob de listen")

    cdn_env = (TOPO / "cdn-edge" / ".env.example").read_text(encoding="utf-8")
    if "TRUSTED_PROXIES=" not in cdn_env:
        errors.append("cdn-edge: falta TRUSTED_PROXIES")
    trusted_line = next(
        (line for line in cdn_env.splitlines() if line.startswith("TRUSTED_PROXIES=")),
        "TRUSTED_PROXIES=",
    )
    if trusted_line.strip() == "TRUSTED_PROXIES=":
        errors.append("cdn-edge: TRUSTED_PROXIES vazio")
    if "173.245.48.0/20" not in trusted_line:
        errors.append("cdn-edge: TRUSTED_PROXIES sem snapshot Cloudflare")
    cdn_caddy_env = (TOPO / "cdn-edge" / ".env.caddy.example").read_text(encoding="utf-8")
    if "172.28.0.2/32" not in cdn_caddy_env or "173.245.48.0/20" not in cdn_caddy_env:
        errors.append("cdn-edge caddy: TRUSTED_PROXIES precisa do Caddy e do snapshot")
    caddy_compose = (TOPO / "cdn-edge" / "docker-compose.caddy.yml").read_text(
        encoding="utf-8"
    )
    if "TRUSTED_PROXIES:" in caddy_compose:
        errors.append("cdn-edge caddy compose sobrescreve TRUSTED_PROXIES")
    checklist = (TOPO / "cdn-edge" / "CHECKLIST.md").read_text(encoding="utf-8")
    if "Authenticated Origin Pulls" not in checklist:
        errors.append("cdn-edge: CHECKLIST sem Authenticated Origin Pulls")
    cdn_caddyfile = (TOPO / "cdn-edge" / "Caddyfile").read_text(encoding="utf-8")
    if "client_auth" not in cdn_caddyfile or "origin-pull" not in cdn_caddyfile:
        errors.append("cdn-edge: Caddyfile sem client_auth de origin pulls")
    if "header_up X-Forwarded-For {http.request.header.X-Forwarded-For}" in cdn_caddyfile:
        errors.append("Caddyfile reescreve XFF com o valor do cliente")
    cdn_lock = (TOPO / "cdn-edge" / "ORIGIN_LOCK.md").read_text(encoding="utf-8")
    if "ufw allow 80/tcp" in cdn_lock:
        errors.append("cdn-edge: ORIGIN_LOCK abre 80 ao mundo")

    site_compose = (TOPO / "vps-site" / "docker-compose.yml").read_text(encoding="utf-8")
    site_caddy = (TOPO / "vps-site" / "docker-compose.caddy.yml").read_text(encoding="utf-8")
    if "caddy:" in site_compose and '"443:3443"' in site_compose:
        errors.append("vps-site: Caddy e Ferroada 443 no mesmo compose")
    if '"443:3443"' in site_caddy:
        errors.append("vps-site caddy compose publica 443 no Ferroada")
    if "caddy:" not in site_caddy:
        errors.append("vps-site: falta compose Caddy separado")

    sk = TOPO / "_skeleton"
    if not sk.is_dir():
        errors.append("falta _skeleton")

    if errors:
        fail("\n".join(errors))
    print("packs fail-closed: ok")


if __name__ == "__main__":
    main()
