# VPS + Supabase auto-hospedado

Ferroada à frente do Kong. Não inspeciona Postgres.

Não é um modo `init` — copie esta pasta ou, quando o subcomando existir, `ferroada init --topology vps-supabase-selfhost`.

| Ficheiro | Função |
| --- | --- |
| `ferroada.toml` | hosts e backend |
| `.env.example` | knobs que o 0.6.0 já honra (caminho Ferroada termina TLS) |
| `.env.caddy.example` | mesmo, com Caddy na frente |
| `docker-compose.yml` | Ferroada publica 80/443 |
| `docker-compose.caddy.yml` | Caddy publica 80/443 |
| `ferroada.service` | systemd em 3000/3443 |
| `Caddyfile` / `nginx.conf.snippet` | TLS local na frente |
| `ORIGIN_LOCK.md` | firewall e overlay |
| `VISIBILIDADE.md` | o que o proxy vê |
| `CHECKLIST.md` | passos em pt-BR |
