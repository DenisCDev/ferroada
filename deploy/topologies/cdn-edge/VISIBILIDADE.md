# O que este modo vê

HTTP que o CDN encaminha a esta VPS, com X-Forwarded-For dos CIDRs em TRUSTED_PROXIES.

# O que este modo não vê

Ataque volumétrico L3/L4 absorvido (ou não) pelo CDN. Se o link da VPS saturar, o Ferroada não tem 429 milagroso.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
