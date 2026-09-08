# O que este modo vê

HTTP/1.1 e HTTP/2 da aplicação atrás deste proxy, com WAF regex, DLP e rate/behavior por site.

# O que este modo não vê

Tráfego que não passa nesta VPS. SQL, RLS, WebSocket, HTTP/3, gRPC protobuf.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
