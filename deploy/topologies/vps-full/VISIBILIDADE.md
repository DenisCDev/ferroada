# O que este modo vê

HTTP da app nesta VPS. Se juntar Kong na overlay, o HTTP do Kong também — só depois de o declarar no toml.

# O que este modo não vê

Painel Next (não sobe em produção). SQL/RLS se houver Postgres local.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
