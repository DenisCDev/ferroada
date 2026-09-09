# VPS só API

SPA ou estático noutro sítio. Ferroada só à frente da API.

Copie esta pasta ou gere com `ferroada init --topology vps-api`.

| Ficheiro | Função |
| --- | --- |
| `ferroada.toml` | hosts e backend |
| `.env.example` | knobs que o 0.6.0 já honra (caminho Ferroada termina TLS) |
| `.env.caddy.example` | Caddy na frente, com `PROXY_PROTOCOL=true` |
| `docker-compose.yml` | Ferroada publica 80/443 |
| `docker-compose.caddy.yml` | Caddy publica 80/443 |
| `ferroada.service` | systemd em 3000/3443; `ferroada.privileged.service` é :80+:443+cap |
| `Caddyfile` / `nginx.conf.snippet` | TLS local na frente |
| `ORIGIN_LOCK.md` | firewall e overlay |
| `VISIBILIDADE.md` | o que o proxy vê |
| `CHECKLIST.md` | passos em pt-BR |
