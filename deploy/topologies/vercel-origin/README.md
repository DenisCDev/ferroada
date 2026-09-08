# Vercel atrás de uma VPS

O Ferroada **não** é uma serverless function. A VPS é o origin público; a Vercel fica upstream.

Copie esta pasta ou gere com `ferroada init --topology vercel-origin`.

| Ficheiro | Função |
| --- | --- |
| `ferroada.toml` | hosts e backend |
| `.env.example` | knobs que o 0.6.0 já honra (caminho Ferroada termina TLS) |
| `.env.caddy.example` | mesmo, com Caddy na frente |
| `docker-compose.yml` | Ferroada publica 80/443 |
| `docker-compose.caddy.yml` | Caddy publica 80/443 |
| `ferroada.service` | systemd em 3000/3443; `ferroada.privileged.service` é :80+:443+cap |
| `Caddyfile` / `nginx.conf.snippet` | TLS local na frente |
| `ORIGIN_LOCK.md` | firewall e overlay |
| `VISIBILIDADE.md` | o que o proxy vê |
| `CHECKLIST.md` | passos em pt-BR |
