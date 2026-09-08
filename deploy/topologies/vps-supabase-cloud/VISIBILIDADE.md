# O que este modo vê

Opção 1 (default): só o BFF/app. Opção 2: também o host {{SUPABASE_HOST}} para o projecto Cloud.

# O que este modo não vê

Na opção 1, login, JWT e PostgREST da Cloud **não** passam aqui. RLS no Supabase continua a ser a autorização.

O Ferroada não substitui Anycast nem mitigação DDoS L3/L4. Se o link da VPS saturar, o processo não responde 429 milagroso.

WebSocket não é inspecionado neste binário. HTTP/3 não tem listener. gRPC chega como content-type não textual.
