# Packs de topologia

Cada pasta é um modo de instalação fail-closed. Copie **uma**. `_skeleton/` não é um modo.

| Pasta | Quando usar |
| --- | --- |
| `vps-site` | VPS com o site (frontend + backend) |
| `vps-api` | VPS só com a API |
| `vps-supabase-selfhost` | API + Supabase auto-hospedado (Kong) |
| `vps-supabase-cloud` | API na VPS, Supabase Cloud (browser fala com `*.supabase.co`) |
| `vps-full` | Tudo na VPS |
| `hostinger-origin` | Estático na Hostinger; Ferroada numa VPS à frente |
| `vercel-origin` | App na Vercel; Ferroada numa VPS à frente |
| `cdn-edge` | Internet → Cloudflare/Fastly/Akamai → Ferroada → backend (recomendado) |

Hostinger e Vercel **não** correm o binário. A VPS é o origin público.

Dashboard em loopback. Produção não mapeia a porta 9000. Token em `DASHBOARD_TOKEN`.
