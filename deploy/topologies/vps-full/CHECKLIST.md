# Checklist — `vps-full`

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

O unit escuta 3000/3443, igual ao binário. Não promete :80. Coloque o binário em `/usr/local/bin/ferroada` antes. Se o Caddy corre no host, `reverse_proxy 127.0.0.1:3000` e `TRUSTED_PROXIES=127.0.0.1/32,::1/128`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ferroada
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

## Stack

- Produção: Ferroada + app. **Não** sobe o painel Next. Distroless não o inclui.
- Supabase self-host: não está neste Compose. Junte o stack oficial na overlay e um `[[sites]]` para o Kong, como em `vps-supabase-selfhost`.
- Liveness: o 0.6.0 expõe `/healthz` no dashboard em loopback. Sem curl na imagem; não há HEALTHCHECK Docker.
