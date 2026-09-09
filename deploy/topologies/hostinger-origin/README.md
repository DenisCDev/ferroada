# Hostinger atrás de uma VPS

O Ferroada **não** corre em shared hosting Hostinger. A VPS é o origin público.

Copie esta pasta ou gere com `ferroada init --topology hostinger-origin`.

| Ficheiro | Função |
| --- | --- |
| `ferroada.toml` | hosts e backend |
| `.env.example` | knobs que o binário honra, incluindo `DLP_ACTION=monitor` e `ORIGIN_SECRET_*` |
| `.env.caddy.example` | Caddy na frente, com `PROXY_PROTOCOL=true` |
| `docker-compose.yml` | Ferroada publica 80/443 |
| `docker-compose.caddy.yml` | Caddy publica 80/443 |
| `ferroada.service` | systemd em 3000/3443; `ferroada.privileged.service` é :80+:443+cap |
| `Caddyfile` / `nginx.conf.snippet` | TLS local na frente |
| `ORIGIN_LOCK.md` | firewall e overlay |
| `VISIBILIDADE.md` | o que o proxy vê |
| `CHECKLIST.md` | passos em pt-BR |
