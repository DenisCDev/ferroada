# O que este modo vê

A API. Rate limit, WAF e DLP só nestes pedidos.

# O que este modo não vê

O JavaScript/CSS hospedado na CDN, Hostinger ou Vercel. XSS reflectido no estático não passa neste processo.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
