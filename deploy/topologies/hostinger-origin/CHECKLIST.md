# Checklist — `hostinger-origin`

1. Esta pasta corre **numa VPS ou VM**. O Ferroada não é serverless nem shared hosting.
2. Copie `.env.example` para `.env`. Substitua `{{PUBLIC_HOST}}`, `{{ORIGIN}}` e o token.
   ```bash
   openssl rand -hex 32
   ```
   Cole o resultado em `DASHBOARD_TOKEN`. Não deixe o placeholder.
3. Substitua `{{PUBLIC_HOST}}` em `ferroada.toml` e no `Caddyfile`. O `backend` no toml já é um URL `http://`/`https://` (o processo resolve DNS no arranque — se for a sua app, mude esse URL **antes** de subir).
4. Escolha **um** caminho de TLS — nunca os dois na :443:
   - Há `fullchain.pem` e chave: copie `.env.example` → `.env`, descomente `TLS_CERT_PATH` / `TLS_KEY_PATH`, use `docker-compose.yml`.
   - Não há: copie `.env.caddy.example` → `.env.caddy` e use `docker-compose.caddy.yml` (Caddy publica 80 e 443; Ferroada só na overlay).
5. Escolha **Docker ou systemd**, não os dois. Com Docker, o dashboard só escuta no loopback do anfitrião; túnel: `ssh -L 9000:127.0.0.1:9000 usuario@vps`. Com systemd, o processo liga `127.0.0.1:9000` no próprio host.
6. Se o Compose sobe um serviço `app`, troque `APP_IMAGE` pela imagem real. Confirme que a app não tem `ports:` públicos.
7. Sem edge na frente, deixe `TRUSTED_PROXIES` vazio: o processo ignora `X-Forwarded-For` e já o diz no log. Isso é o esperado, não um furo silencioso.

## systemd

O unit desta pasta (`ferroada.service`) escuta 0.0.0.0:3000/3443 via `PROXY_LISTEN`/`TLS_LISTEN`, sem cap. Não promete :80.
`ferroada.privileged.service` publica :80/:443 **e** traz `AmbientCapabilities` + `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` — o binário não é setuid; knob sem cap falha o bind. Copie **um** dos dois para `/etc/systemd/system/ferroada.service`, nunca os dois.
`ferroada init --listen-mode privileged` emite o unit :80+cap; `--listen-mode proxied` emite 127.0.0.1:3000 sem cap e o Caddy na frente.
Coloque o binário em `/usr/local/bin/ferroada` antes. Se o Caddy corre no host, use o `Caddyfile` desta pasta — não um `reverse_proxy` nu. Se esse Caddyfile tem `proxy_protocol v2`, o env tem de ligar `PROXY_PROTOCOL` (`.env.caddy.example`, nunca `.env.example`); senão o Ferroada recusa a conexão. `TRUSTED_PROXIES=127.0.0.1/32,::1/128` (mais o snapshot CDN, se houver).

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ferroada
sudo mkdir -p /var/lib/ferroada/spool
sudo chown ferroada:ferroada /var/lib/ferroada/spool
sudo chmod 0700 /var/lib/ferroada/spool
sudo cp tmpfiles.d/ferroada.conf /etc/tmpfiles.d/ferroada.conf
sudo systemd-tmpfiles --create
sudo mkdir -p /etc/ferroada
sudo cp ferroada.toml /etc/ferroada/
sudo cp .env /etc/ferroada/env
sudo chown -R ferroada:ferroada /etc/ferroada
sudo cp ferroada.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ferroada
sudo systemctl is-active ferroada
sudo journalctl -u ferroada -n 20 --no-pager
```

Sucesso: o log contém `Ferroada proxy ready` e `Dashboard ready`. Parar: `docker compose down` ou `sudo systemctl stop ferroada`.

## Isto precisa de uma VPS

Se a ideia era «instalar o Ferroada na Hostinger»: pare. Este processo precisa de uma VM. Alugue uma VPS ou use só o CDN na frente da Hostinger, sem Ferroada.

## `--static-placement` (três receitas)

1. **ferroada-front (default):** a VPS é o origin público; a Hostinger só aceita o IP desta VPS. Header secreto de origem ainda não existe neste binário — a defesa é a allowlist de IP.
2. **public:** o estático na Hostinger é público (o Ferroada **não** o protege). `{{ORIGIN}}` é só a API na VPS. Leia o `VISIBILIDADE.md`.
3. **cdn:** Cloudflare na frente do Ferroada; Hostinger como origin do cache de estático. Junte o pack `cdn-edge`.

`/readyz` no dashboard testa TCP contra o backend. Aqui o backend é a internet — use `/healthz` (liveness do processo), não `/readyz`, para probe.
