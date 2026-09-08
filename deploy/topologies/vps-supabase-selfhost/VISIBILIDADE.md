# O que este modo vê

HTTP que entra no Kong (PostgREST, GoTrue, Storage HTTP, Realtime via upgrade).

# O que este modo não vê

SQL, RLS, replicação, bytes de storage profundo, Studio. Multipart não textual fica inspeção incompleta.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
