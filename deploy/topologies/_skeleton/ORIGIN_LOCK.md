# Travamento da origem

O Ferroada é o único processo público. O backend não deve ser alcançável da internet.

## Firewall (ufw, exemplo)

Abra só o que o caminho escolhido realmente escuta.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
# Docker mapa 80:3000 / Caddy a publicar 80 e 443:
ufw allow 80/tcp
ufw allow 443/tcp
# systemd sozinho (sem Caddy, sem mapa Docker): o binário escuta 3000/3443
# ufw allow 3000/tcp
# ufw allow 3443/tcp
# 8080 e o dashboard 9000 ficam fechados no filtro público.
ufw enable
```

Caddy no host: `reverse_proxy 127.0.0.1:3000` e `TRUSTED_PROXIES=127.0.0.1/32,::1/128`. Sem isso todos os clientes viram loopback. Feche 3000/3443 no filtro público.

## Docker

- Backend sem `ports:` no anfitrião. A overlay `origin` tem saída para a internet (webhooks, APIs); o que trava entrada pública é a ausência de `ports:`.
- Dashboard: no systemd, `DASHBOARD_BIND=127.0.0.1`. No Docker, o processo liga `0.0.0.0:9000` **dentro** do contêiner (token obrigatório) e o Compose só mapeia `127.0.0.1:9000` no anfitrião — não na internet. Túnel: `ssh -L 9000:127.0.0.1:9000 usuario@vps`.
- Token Bearer em `DASHBOARD_TOKEN`. Não deixe o placeholder.

## Header secreto de origem

O binário 0.6.0 ainda não injeta um header de origem. Até esse knob existir, a defesa é IP allowlist / overlay interna, não um segredo no pedido.
