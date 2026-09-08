# O que este modo vê

Todo o HTTP da app nesta VPS (páginas e API).

# O que este modo não vê

WebSocket inspecionado, HTTP/3, tráfego que o cliente mande directo à app se 8080 estiver aberto.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
