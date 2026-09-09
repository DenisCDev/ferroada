# Travamento da origem

O Ferroada é o único processo público. O backend não deve ser alcançável da internet.

## Firewall (ufw, exemplo)

Abra só o que o caminho escolhido realmente escuta.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
# Docker mapa 80:3000 / Caddy a publicar 80 e 443:
# Não abra 80/443 ao mundo. Só CIDRs de deploy/cidrs/cloudflare.txt:
# ufw allow from 173.245.48.0/20 to any port 80 proto tcp
# ufw allow from 173.245.48.0/20 to any port 443 proto tcp
# (uma regra por prefixo do snapshot)
# systemd sozinho (sem Caddy, sem mapa Docker): o binário escuta 3000/3443
# ufw allow 3000/tcp
# ufw allow 3443/tcp
# 8080 e o dashboard 9000 ficam fechados no filtro público.
ufw enable
```

Caddy no host: use o `Caddyfile` desta pasta, não um `reverse_proxy` nu. Este pack Cloudflare **não** prefixa PROXY v2. `TRUSTED_PROXIES=127.0.0.1/32,::1/128` mais o snapshot. Feche 3000/3443 no filtro público.

## Docker

- Backend sem `ports:` no anfitrião. A overlay `origin` tem saída para a internet (webhooks, APIs); o que trava entrada pública é a ausência de `ports:`.
- Dashboard: no systemd, `DASHBOARD_BIND=127.0.0.1`. No Docker, o processo liga `0.0.0.0:9000` **dentro** do contêiner (token obrigatório) e o Compose só mapeia `127.0.0.1:9000` no anfitrião — não na internet. Túnel: `ssh -L 9000:127.0.0.1:9000 usuario@vps`.
- Token Bearer em `DASHBOARD_TOKEN`. Não deixe o placeholder.

## Header secreto de origem

O Ferroada injeta `ORIGIN_SECRET_HEADER` (default `X-Ferroada-Origin`) com o valor de `ORIGIN_SECRET` em cada pedido ao upstream. Vazio = não injeta. A app deve recusar pedidos sem esse valor. O processo não loga o segredo, só o nome do header.

Firewall: só CIDRs Cloudflare (snapshot 2026-09-08). Origin pulls no terminador à frente, não no Pingora.
