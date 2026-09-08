# O que este modo vê

HTTP que chega a esta VPS e segue para a URL de produção da Vercel.

# O que este modo não vê

Invocações serverless que a Vercel faça por si (crons, outras regiões) sem passar nesta VPS. Authz da app continua na Vercel.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
