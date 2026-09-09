# Checklist — `cdn-edge`

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

## Cloudflare (laranja)

A Cloudflare **não** manda PROXY protocol. Este pack **não** liga nenhum protocolo PROXY. A identidade é CIDR + `X-Forwarded-For` (já no 0.6.0).

`TRUSTED_PROXIES` já vem com o snapshot de `deploy/cidrs/cloudflare.txt`. Não o esvazie. Escape hatch (não é o default): apagar a lista e aceitar que o IP passa a ser o socket — o processo loga isso.

Fastly ou Akamai: substitua `TRUSTED_PROXIES` pelo conteúdo de `deploy/cidrs/fastly.txt` ou `akamai.txt` (vírgulas).

## Authenticated Origin Pulls

Em produção atrás da Cloudflare **deve** ligar Authenticated Origin Pulls: o Caddy (ou o terminador TLS **à frente** do Ferroada) verifica o certificado de cliente da Cloudflare. Só CIDR no firewall arranca; origin pulls é a prova de que o peer é a Cloudflare. Client-auth no Pingora ainda não existe neste binário.

1. Cloudflare → SSL/TLS → Origin Server → Authenticated Origin Pulls: On.
2. Instale o CA da Cloudflare no Caddy/terminador à frente — **não** no listener 3443 do Ferroada neste pack, a menos que o Ferroada seja o único TLS e você saiba que o 0.6.0 não valida client cert.
3. Firewall da VPS: só os CIDRs de `deploy/cidrs/cloudflare.txt` nas 80/443.

`FORCE_HTTPS=true` (HSTS só com isto).
