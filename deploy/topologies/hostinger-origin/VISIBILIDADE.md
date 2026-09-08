# O que este modo vê

O que o Ferroada encaminha para `{{ORIGIN}}` (API e/ou estático, conforme a receita).

# O que este modo não vê

Receita `public`: o estático na Hostinger **não** passa aqui. Shared hosting Hostinger não oferece mTLS de origem.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
