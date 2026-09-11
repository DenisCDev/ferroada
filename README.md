<h1 align="center">Ferroada</h1>

<p align="center">
  <b>Na frente do seu app. No seu servidor.</b><br>
  Bloqueia o ataque e segura o que não podia vazar. Você não mexe no código e não manda o tráfego pra nuvem de ninguém.<br>
  <sub><i>"I will give you a name, and I shall call you Sting."</i></sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-pingora%200.8.1-D4A24E?labelColor=171310" alt="Rust com Pingora 0.8.1">
  <img src="https://img.shields.io/badge/bin%C3%A1rio%20%C3%BAnico-distroless%20~20MB-43A48E?labelColor=171310" alt="binário único, container distroless de ~20MB">
  <img src="https://img.shields.io/badge/deps%20externas-zero-43A48E?labelColor=171310" alt="zero dependências externas">
  <img src="https://img.shields.io/badge/cargo%20audit-no%20build-D4A24E?labelColor=171310" alt="cargo audit roda no build">
</p>

<p align="center">
  <img src="assets/mtg-sting.jpg" width="640" alt="Ferroada, o Punhal Reluzente — arte de Nino Is, Tales of Middle-earth (2023)">
</p>

> *"Sting, the Glinting Dagger"*, que a edição brasileira de **Magic: The Gathering** imprimiu como
> **"Ferroada, o Punhal Reluzente"**. Arte de Nino Is, Tales of Middle-earth (2023).
> A lâmina acende quando o inimigo se aproxima. É exatamente o serviço.

**Todo ataque chega pela mesma porta que o tráfego legítimo.** SQL injection, XSS,
path traversal, scanner rodando a lista de sempre — tudo entra como requisição HTTP
comum, e a maioria dos sistemas só percebe quando o estrago já está no log. Corrigir
o backend é o caminho certo, e também o mais lento: cada framework, cada versão,
cada sistema legado é uma frente nova.

O Ferroada ataca o problema pela infraestrutura: fica **na frente do seu app,
no seu servidor**, sem alterar uma linha dele. Bloqueia ataque conhecido
na entrada, mascara dado sensível na saída e mantém um score por site e rede do cliente
— quem age como scanner é freado antes de achar alguma coisa. DDoS fica no CDN.
Quem olha a request da sua API é o Ferroada, no seu servidor. Construído com
[Pingora 0.8.1](https://github.com/cloudflare/pingora/releases/tag/0.8.1), o motor de proxy da Cloudflare,
compilado num binário único e distribuído como container distroless de ~20MB.
Esta versão limita por padrão os headers HTTP/2 decodificados a 64 KiB e cada
conexão HTTP/2 a 100 streams simultâneos, rejeitando headers excessivos com 431
antes da aplicação. O Ferroada fixa a versão exata no manifesto e no lockfile
para que build local, container e CI usem a mesma base.

```
Internet → [Ferroada :3000] → Seu Sistema :8080
                ↓
         Dashboard 127.0.0.1:9000
```

**Multi-site:** um único deploy protege vários backends simultaneamente:

```
Internet
  │
  ├── meusite.com       ──→ backend-a:8080
  ├── api.meusite.com   ──→ backend-b:3000
  └── outrosite.com     ──→ backend-c:4000
         │
    [Ferroada :3000]
         │
    Dashboard 127.0.0.1:9000
```

---

## O que o Ferroada protege

### Camada de entrada (WAF)

| Ataque | Onde inspeciona | Exemplo bloqueado |
|--------|----------------|-------------------|
| **SQL Injection** | URI, headers e qualquer body HTTP | `?id=1 UNION SELECT * FROM users` |
| **XSS (Cross-Site Scripting)** | URI, headers e qualquer body HTTP | `<script>alert(1)</script>`, `onerror=`, `javascript:` |
| **Path Traversal** | URI, headers | `../../etc/passwd`, `%2e%2e%2f` |
| **CRLF Injection** | URI, headers, body | `%0d%0aSet-Cookie:` (com skip de multipart no body) |
| **JNDI / Log4Shell** | URI, headers, body | `${jndi:ldap://...}`, inclusive ofuscado |
| **Request Smuggling** | Headers | `Content-Length` duplicado, `CL`+`TE`, `TE` inválido → 400 |
| **Sensitive Path Access** | URI path + profile | `/.env`, `/.git/`, `/phpmyadmin`, `/.aws/credentials` |
| **Bad Bots** | User-Agent | 18 assinaturas: sqlmap, nikto, nuclei, etc. |
| **Brute Force / DDoS básico** | Site + IPv4 ou prefixo IPv6 /64 | Rate limit sliding window (config via env) |

A detecção de SQLi cobre cinco categorias — clássica (`UNION SELECT`, `OR 1=1`),
stacked queries (`;DROP`), blind/time-based (`SLEEP`, `BENCHMARK`, `WAITFOR`),
abuso de função (`EXTRACTVALUE`, `LOAD_FILE`) e evasão por comentário
(`/*!UNION*/`). A de XSS reconhece ~40 event handlers (`ontoggle`,
`onpointerover`, `onbegin`, ...) além de `confirm()`, `prompt()`, `Function()`,
`<math>`, `<base>` e `url(javascript:)`.

#### Paths bloqueados por padrão

Arquivos e diretórios que nunca deveriam ser expostos publicamente:

```
/.env  /.git/  /.svn/  /.hg/  /.DS_Store  /.htaccess  /.htpasswd
/wp-config.php
/phpmyadmin/  /phpinfo.php  /server-status  /server-info
/actuator/  /console  /debug
/config.php  /config.yml  /config.json  /database.yml
/docker-compose.yml  /Dockerfile  /.dockerenv
/.ssh/  /id_rsa  /id_ed25519  /.aws/credentials
/.bash_history  /.npmrc  /.vscode  /.idea  /web.config
```

O profile `generic` não presume que `/wp-admin`, `/wp-login.php` e `xmlrpc.php`
sejam ataques. `wordpress` monitora esses acessos sem bloquear; `strict` os
bloqueia. Arquivos realmente sensíveis, como `wp-config.php`, continuam
bloqueados em todos os profiles.

L0 (regex) fica sempre ligado. L1 é um sidecar Coraza com CRS 4.25 LTS no
Unix socket, opt-in (`WAF_ENGINE=coraza`). O binário do Ferroada não liga
Coraza: um crash no ruleset não derruba o proxy. Timeout default 500 ms;
o processo só marca o engine `coraza` depois do ready probe. Sidecar
ausente numa rota `require_complete` responde 403 e conta
`waf_engine_unavailable` — não desliga o WAF em silêncio.

Paranoia CRS separa `blocking` de `executing`: regras do nível executing
correm sem necessariamente bloquear. Shadow avalia L1, grava rule ID e
anomaly score no evento, e não devolve 403. Exclusões por site, rota,
parâmetro e content-type ficam no TOML (`[waf.l1]`, `[[sites.l1.exclusions]]`).
Ver `deploy/coraza/`.

OpenAPI 3.0/3.1 é opt-in por site: um path no TOML (`openapi = "./openapi.yaml"`
ou `openapi = { spec = "./openapi.yaml", unknown_endpoint = "observe" }`).
O spec é compilado no arranque. Sem spec o proxy continua exatamente como
hoje. Com spec, o Ferroada valida método, rota, path/query/header, content-type
e o JSON do body (tipos, required, enum, campos a mais). Endpoint desconhecido
é observe ou deny (no pack o default é observe; em rota `require_complete`
sem a chave, deny). Método ou content-type fora do contrato: deny. O evento
diz o path e o campo; o body não entra no log.

JWT/JWKS é opt-in por site (`jwt = { jwks = "...", issuer = "...", audience = "..." }`).
Sem o bloco o site continua igual, inclusive sem `Authorization`. Com o bloco,
o token é a chave de identidade: allowlist de alg (default só RS256/ES256;
`none` recusado; HS* só com `algorithms` explícito e `hmac_secret_env`),
`iss` e `aud` obrigatórios, `exp`/`nbf`/`iat`/`jti` validados, JWKS cacheado
com timeout no fetch e last-known-good se o IdP cair. Bindings no TOML
(`jwt.sub == path.account_id`, `jwt.tenant_id == body.tenant_id`). Rate e
comportamento passam a usar o hash de `sub`/tenant, não só o IP. O token e o
payload não entram no log.

GraphQL é opt-in por site/rota (`graphql = { max_depth = 8, max_operations = 5, introspection = false }`).
Sem o bloco, `POST /graphql` continua só com HTTP/WAF/OpenAPI. Com o bloco, o
proxy parseia o AST (JSON `{"query":...}`, batch em array, ou
`application/graphql`) e aplica tetos de profundidade, complexidade, aliases,
fragments e quantidade de operações. Introspection (`__schema` / `__type`)
nasce desligada em produção. Persisted queries são uma allowlist local de
SHA-256; `persisted_only = true` recusa query solta fora da lista. Quota de
custo usa `jwt.sub` se o site tem JWT, senão o IP. Parse falhou vira
`ParseError` e segue a política da rota (403 em `require_complete`). O evento
diz o limite que estourou (`depth`, `aliases`, …), nunca a query.

gRPC é opt-in por site (`grpc = { descriptor = "./api.pb", allow = ["pkg.Service/Method"], max_message_bytes = "64KiB", reflection = false }`).
Sem o bloco, `application/grpc` (e `+proto`) segue a matriz de protocolo — hoje
`deny`, ou `bypass-explicit` se o operador trocar; o proxy **não** passa a
inspecionar sozinho. Com o bloco, o FileDescriptorSet é compilado no arranque.
Método fora da allowlist devolve 403 e zero bytes no origin. Tamanho por
message (lido no prefixo de 5 bytes do frame) acima de `max_message_bytes`
também 403. O teto conta o payload; o frame no fio tem 5 bytes a mais, então
64KiB de message não cabe no replay HTTP de 64KiB sem `max_decoded_body`. Reflection (`grpc.reflection.v1` / `ServerReflectionInfo`) nasce
desligada; só passa com `reflection = true`. Se o cliente não manda
`grpc-timeout`, o proxy injeta o teto (default 10s) ou nega se
`require_deadline = true`. Protobuf que não casa com o descriptor vira
`ParseError` e segue a política da rota. O evento traz service/method, nunca
o payload. DLP em campo protobuf não existe neste recorte.

#### Inspeção de body

O body de qualquer método permitido é inspecionado antes de chegar ao backend.
O proxy lê **todos** os chunks, aplica o teto de `MAX_BODY_SIZE` também em
`Transfer-Encoding: chunked`, limita a soma dos buffers simultâneos com
`WAF_MAX_IN_FLIGHT_BYTES` e, antes de ler o body, reserva de forma conservadora
o limite das duas cópias simultâneas (inspeção local + replay do Pingora). Se o
cliente mandou `Content-Encoding: gzip`
ou `deflate` o WAF infla uma cópia só para inspecionar — os bytes originais
seguem para o upstream somente depois da decisão. No Pingora 0.8.1, o replay
seguro antes do upstream é limitado a 64KB; por isso `MAX_BODY_SIZE` também é
limitado a 65536 bytes, **exceto** rotas `require_complete` com
`max_decoded_body` — aí os três tetos (bytes no fio, texto do WAF, inflate)
sobem juntos para esse número, o body fica num spool e o origin só recebe
depois do outcome. Sem `max_decoded_body` o processo não cria
`/var/lib/ferroada/spool`. A inspeção registra `complete`, `truncated`,
`unsupported_encoding` ou `unsupported_content_type`. Um gzip gigante é
cortado no teto de inflate da rota (256KB no default), então um zip bomb não
estoura a memória. Rotas sensíveis podem exigir inspeção completa e rejeitar
qualquer outro estado.
JSON é parseado para expor escapes como `\u003c`; form-urlencoded trata `+` e
percent-encoding; GraphQL textual passa pela mesma canonicalização de texto.
gRPC/binário, encodings desconhecidos e multipart não textual ficam explícitos
como inspeção incompleta, de modo que rotas fail-closed não os encaminham por
engano.

### Análise de comportamento (behavioral scoring)

Regra de assinatura pega o ataque conhecido; o score de comportamento pega quem
está **procurando** um. Cada IP acumula pontos por ação suspeita e perde 5
pontos por segundo de bom comportamento:

| Sinal | Pontos |
|-------|--------|
| Bloqueio do WAF | +20 |
| Resposta 401 | +5 |
| Resposta 404 | +3 |
| Request sem User-Agent | +8 |
| Path scan (>30 paths únicos/min) | detectado |
| Rotação de User-Agent (>3 UAs) | detectada |

Cruzou 50 pontos, o cliente é freado; cruzou 80, é banido por 10 minutos. A
identidade inclui site e endereço de rede; IPv6 é agrupado por /64 para evitar
rotação barata dentro do mesmo prefixo. Os
thresholds são configuráveis, o tracking tem teto de 50 mil IPs com limpeza
LRU, e a lógica de decay, scoring e ban tem testes unitários
(`src/behavioral.rs`).

### Hardening de infraestrutura

| Proteção | O que faz | Resposta |
|----------|-----------|----------|
| **Security Headers** | Injeta X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-Permitted-Cross-Domain-Policies em toda resposta | Headers automáticos |
| **Server Header Stripping** | Remove `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-Token`, `X-Runtime` | Informação de infra oculta |
| **HTTP Method Restriction** | Bloqueia TRACE, CONNECT e métodos não configurados | 405 Method Not Allowed |
| **Request Size Limiting** | Limita o body a 64KB antes do upstream e a URI a 8KB | 413 / 414 |
| **Host Validation** | Valida o Host header contra a allowlist `ALLOWED_HOSTS` (previne DNS rebinding) | 421 Misdirected Request |
| **HTTPS Enforcement** | Redireciona HTTP → HTTPS quando TLS está configurado + injeta HSTS | 301 Moved Permanently |
| **Dashboard seguro** | Escuta loopback por padrão; bind externo exige Bearer token | 401 Não autorizado |
| **Multi-encoding Protection** | Decodifica URL e headers recursivamente (máx. 8x), inclusive `%uXXXX` e `+` como espaço na query | Previne bypass `%2525252e`, XSS percent-encoded em header |
| **Upstream timeouts** | `HttpPeer` com connect/read/write; body do cliente tem deadline próprio | Upstream morto não segura o worker |
| **Rate limit com evicção** | Sliding window por site/rede; chaves expiradas saem do mapa; teto configurável | Flood de identidades não cresce a memória para sempre |
| **Trusted proxies** | Só aceita XFF/X-Forwarded-Proto de redes em `TRUSTED_PROXIES` | Evita spoof e rate limit compartilhado pelo balanceador |
| **Limites e backpressure** | Limita headers, requisições em voo, keep-alive e escrita ao cliente | Rejeita exaustão cedo com 431/503 |
| **Dependency Audit** | `cargo audit` roda no build Docker — falha em vulnerabilidades sem exceção documentada e justificada | Build falha |

#### Security headers — filosofia "não quebrar"

**Defaults conservadores** (ainda devem ser validados com a aplicação):
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 0
X-Permitted-Cross-Domain-Policies: none
```

`X-Frame-Options` pode ser alterado com `FRAME_OPTIONS` ou preservado do
upstream com `FRAME_OPTIONS=off`; `SAMEORIGIN` pode quebrar embeds legítimos de
outro origin.

**Condicionais** (só ativam quando você explicitamente configura):
```
Strict-Transport-Security    → só quando FORCE_HTTPS=true
Content-Security-Policy      → só quando CSP_POLICY está definido
Permissions-Policy           → só quando PERMISSIONS_POLICY está definido
```

**Removidos** da resposta (sempre):
```
Server, X-Powered-By, X-AspNet-Version, X-Debug-Token, X-Runtime
```

### Camada de saída (DLP)

| Dado sensível | Padrão detectado | Resultado mascarado |
|---------------|------------------|---------------------|
| **CPF** | `390.533.447-05` (dígito verificador) | `***.***.***-**` |
| **CNPJ** | `04.252.011/0001-10` (dígito verificador) | `**.***.***/****-**` |
| **Cartão** | 13–19 dígitos com Luhn | dígitos viram `*` |
| **Bearer Token** | `Bearer eyJhbGciOi...` | `Bearer [REDACTED]` |

CPF/CNPJ com dígito errado não são mascarados. Paths JSON (`$.user.cpf`) são
opt-in no TOML por site ou rota; sem eles o DLP de blob continua. `DLP_ACTION=block`
não libera nenhum byte ao cliente antes do fim da inspeção.

Se o backend vazar um CPF ou token em resposta textual identity, gzip,
deflate ou brotli, o Ferroada descomprime com limite, mascara e recomprime.
Brotli sem orçamento de inflate é skip observável, não “limpo”. Quando pode
transformar uma resposta, remove `Content-Length`, `ETag`, `Content-MD5`,
`Digest`, `Content-Digest` e `Repr-Digest`, pois deixariam de representar os
bytes enviados. SSE, gRPC, NDJSON, WebSocket e respostas assinadas passam sem
transformação para não corromper o protocolo; cada skip vira evento observável.
Pedidos de range são removidos antes do upstream e respostas textuais parciais
inesperadas são rejeitadas, impedindo que `206` contorne o mascaramento. O buffer é limitado a
1MB por resposta e 64MB no processo por padrão.

### Monitoramento

<p align="center">
  <img src="assets/dashboard.png" width="880" alt="Painel do Ferroada em preto e branco: visão geral com requisições, bloqueios, tráfego limpo e lista de eventos">
</p>

O binário serve JSON em `http://localhost:9000/api/metrics` e um HTML mínimo na
mesma porta. Quando há token, o HTML pede a credencial e a mantém apenas no
`sessionStorage` da aba; falhas de atualização ficam visíveis na página.

O painel Next (preto e branco, `web/`) é a interface: Visão geral e Eventos, atualização a cada 5 s. Se o proxy não estiver no ar, o painel mostra dados de demonstração.

```bash
cd web
npm install
cp .env.example .env.local
npm run dev    # http://localhost:3100
```

`FERROADA_URL` (default `http://127.0.0.1:9000`) e `FERROADA_TOKEN` (se
`DASHBOARD_TOKEN` estiver setado) ficam no servidor Next, não no browser. O
painel só entrega métricas depois que o visitante informa `FERROADA_WEB_TOKEN`;
essa credencial separada fica no `sessionStorage` da aba e é enviada como Bearer
apenas para o mesmo servidor Next.

---

## O que o Ferroada NÃO protege

Estas vulnerabilidades são de **lógica de aplicação** e precisam ser corrigidas
no código do backend — um proxy que prometesse resolvê-las estaria mentindo:

| Vulnerabilidade | Por que proxy não resolve |
|----------------|--------------------------|
| **IDOR** (Insecure Direct Object Reference) | Só o backend sabe se o user A pode acessar o recurso do user B |
| **Mass Assignment** | Só o backend sabe quais campos são permitidos em cada request |
| **Race Condition** | Controle de concorrência é responsabilidade do banco/backend |
| **JWT / secret fraco** | Configuração de autenticação do backend |
| **Senha em texto puro / hash sem salt** | Decisão de armazenamento no banco de dados |
| **Manipulação de roles** | Autorização é lógica de negócio do backend |
| **Engenharia social** | Fator humano — nenhum software resolve |
| **Game hacking / WebSocket** | O Ferroada não inspeciona tráfego WebSocket |

**O Ferroada é a primeira linha de defesa (infraestrutura), não a única.** Para
segurança completa, o backend precisa de validação própria.

---

## Quick start

Laboratório na sua máquina. Produção: copie um pack em [`deploy/topologies/`](deploy/topologies/) — o dashboard fica em loopback e **não** se publica na internet.

### 1. Build

```bash
docker build -t ferroada .
```

### 2. Run

```bash
docker run -d \
  -e TARGET_URL=http://host.docker.internal:8080 \
  -e RUST_LOG=info \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -e RATE_LIMIT_MAX=100 \
  -e RATE_LIMIT_WINDOW=60 \
  -p 3000:3000 \
  --name ferroada \
  ferroada
```

O dashboard escuta `127.0.0.1:9000` **dentro** do contêiner. No laboratório, entre com `docker exec` ou publique só no loopback do anfitrião. Em produção use o túnel `ssh -L 9000:127.0.0.1:9000`.

### 3. Testar

```bash
# Request normal (passthrough)
curl -i http://localhost:3000/

# SQL Injection → 403
curl -i "http://localhost:3000/?id=1 UNION SELECT * FROM users"

# XSS → 403
curl -i "http://localhost:3000/?q=<script>alert(1)</script>"

# Path Traversal → 403
curl -i "http://localhost:3000/../../etc/passwd"

# Sensitive path → 403
curl -i http://localhost:3000/.env
curl -i http://localhost:3000/.git/config

# Body injection (POST) → 403
curl -i -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","pass":"x\" OR 1=1--"}'

# Rate limit → 429 (após 100 requests)
for i in $(seq 1 105); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:3000/
done

# Dashboard (só se publicou o loopback do anfitrião)
curl -H 'Authorization: Bearer troque-por-um-token-longo' \
  http://127.0.0.1:9000/api/metrics
```

---

## Modos de instalação

O binário é um processo Pingora. Não corre na Hostinger nem como função na Vercel. Cada pasta em `deploy/topologies/` é um pack fail-closed: toml, env, Compose, unit systemd, origin-lock e um `VISIBILIDADE.md` honesto.

| Modo | Quando usar |
|------|-------------|
| [`vps-site`](deploy/topologies/vps-site/) | VPS com o site (frontend + backend) |
| [`vps-api`](deploy/topologies/vps-api/) | VPS só com a API |
| [`vps-supabase-selfhost`](deploy/topologies/vps-supabase-selfhost/) | API + Supabase auto-hospedado (Kong) |
| [`vps-supabase-cloud`](deploy/topologies/vps-supabase-cloud/) | API na VPS, Supabase Cloud |
| [`vps-full`](deploy/topologies/vps-full/) | Tudo na VPS |
| [`hostinger-origin`](deploy/topologies/hostinger-origin/) | Estático na Hostinger; Ferroada numa VPS à frente |
| [`vercel-origin`](deploy/topologies/vercel-origin/) | App na Vercel; Ferroada numa VPS à frente |
| [`cdn-edge`](deploy/topologies/cdn-edge/) | Internet → CDN → Ferroada → backend (recomendado) |

Comece pelo `CHECKLIST.md` do modo. TLS: o Ferroada termina se houver `fullchain.pem`; senão Caddy na frente. Os dois nunca publicam a 443 ao mesmo tempo. CIDRs do edge: `deploy/cidrs/` (snapshot datado, sem fetch no processo).

```bash
ferroada init --topology vps-api --origin http://127.0.0.1:8080 --public-host api.exemplo.com --non-interactive
ferroada init --topology cdn-edge --origin http://127.0.0.1:8080 --public-host api.exemplo.com --trusted-proxies auto --non-interactive
ferroada healthcheck   # GET 127.0.0.1:9000/healthz; exit 0/1. Distroless não tem curl.
ferroada reload        # SIGHUP: tenta o TOML novo; se falhar, last-known-good
ferroada policy compile --config ferroada.toml -o ferroada.policy.json
ferroada policy sign --key priv.pem --in ferroada.policy.json -o ferroada.policy.sig
```

`--trusted-proxies auto` copia o snapshot em `deploy/cidrs/` (embutido no binário). Zero HTTP. Para actualizar a lista: `ferroada cidrs update` (HTTP só neste comando; `--cidrs-from-network` não existe no `init`). `--listen-mode privileged` emite :80/:443 **e** `CAP_NET_BIND_SERVICE`; `proxied` deixa o processo em 127.0.0.1:3000 com Caddy na frente.

---

## Configuração

Toda a configuração é feita por variáveis de ambiente:

| Variável | Default | Descrição |
|----------|---------|-----------|
| `TARGET_URL` | *(obrigatória\*)* | URL do sistema upstream — modo single-site (ex.: `http://meu-sistema:8080`) |
| `RUST_LOG` | `info` | Nível de log (`debug`, `info`, `warn`, `error`) |
| `RATE_LIMIT_MAX` | `100` | Máximo de requests por site/rede na janela |
| `RATE_LIMIT_WINDOW` | `60` | Janela de tempo em segundos |
| `RATE_LIMIT_MAX_IPS` | `50000` | Teto de identidades de risco no mapa (evicção acima disso) |
| `REPLICA_COUNT` | `1` | Divide conservadoramente os budgets de rate/behavior entre as réplicas |
| `RISK_SESSION_COOKIE` | `session` | Cookie de sessão incluído por hash na identidade de risco |
| `RISK_API_KEY_HEADER` | `X-API-Key` | Header de API key incluído por hash na identidade de risco |
| `UPSTREAM_CONNECT_TIMEOUT` | `5` | Segundos para o `connect()` no backend |
| `UPSTREAM_READ_TIMEOUT` | `30` | Segundos máximos lendo a resposta do backend |
| `UPSTREAM_WRITE_TIMEOUT` | `30` | Segundos máximos escrevendo no backend |
| `BODY_READ_TIMEOUT` | `10` | Segundos máximos lendo o body do cliente |
| `DOWNSTREAM_WRITE_TIMEOUT` | `30` | Segundos máximos escrevendo a resposta para o cliente |
| `DOWNSTREAM_KEEPALIVE_SECS` | `30` | Idle timeout da conexão HTTP/1 com o cliente |
| `DOWNSTREAM_KEEPALIVE_REQUESTS` | `100` | Máximo de requests reutilizando a mesma conexão HTTP/1 |
| `MAX_IN_FLIGHT_REQUESTS` | `1024` | Teto de requisições simultâneas; excedentes recebem 503 |
| `CONNECTION_RATE_MAX` | `60` | Novas conexões aceitas por IP na janela, antes de TLS/HTTP |
| `CONNECTION_RATE_WINDOW` | `1` | Janela do limite de conexões, em segundos |
| `CONNECTION_RATE_MAX_IPS` | `50000` | Teto de IPs rastreados no filtro de conexão |
| `GLOBAL_CONNECTION_RATE_MAX` | `10000` | Novas conexões globais aceitas por janela, antes de TLS/HTTP |
| `MAX_ACTIVE_CONNECTIONS` | `10000` | Teto de sessões downstream ativas, incluindo espera por headers HTTP/1 |
| `MAX_HEADER_COUNT` | `100` | Máximo de headers por request |
| `MAX_HEADER_BYTES` | `65536` | Soma máxima de nomes e valores dos headers |
| `MAX_UPSTREAM_RETRIES` | `0` | Novas tentativas após a primeira; limitado a no máximo 3. Com vários origins, GET/HEAD/OPTIONS ganha ao menos 1 retry se o origin resetar antes de responder. POST/PATCH não retentam. |
| `PROXY_THREADS` | CPUs disponíveis (máx. 64) | Threads por serviço |
| `GRACE_PERIOD_SECS` | `5` | Espera antes da fase final de shutdown gracioso |
| `GRACEFUL_SHUTDOWN_TIMEOUT_SECS` | `30` | Limite da fase final de shutdown gracioso |
| `TLS_CERT_PATH` | *(opcional)* | Caminho para o certificado TLS (fullchain.pem) |
| `TLS_KEY_PATH` | *(opcional)* | Caminho para a chave privada TLS |
| `PROXY_LISTEN` | `0.0.0.0:3000` | Endereço do listener HTTP |
| `TLS_LISTEN` | `0.0.0.0:3443` | Endereço do listener HTTPS (só se `TLS_CERT_PATH`/`TLS_KEY_PATH`) |
| `DASHBOARD_PORT` | `9000` | Porta do dashboard de monitoramento |
| `DASHBOARD_BIND` | `127.0.0.1` | IP do dashboard; bind não-loopback exige token |
| `DASHBOARD_TOKEN` | *(vazio em loopback)* | Token Bearer; obrigatório fora de loopback e com `FERROADA_PRODUCTION=true` |
| `FERROADA_PRODUCTION` | *(unset)* | Se `true`, o token é obrigatório mesmo em 127.0.0.1. O HTML continua público (formulário); `/api/metrics` e `/metrics` exigem Bearer |
| `FERROADA_POLICY_PUBKEY` | *(unset)* | Chave pública Ed25519 (PEM, hex ou base64). Opt-in: sem ela o TOML solto arranca. Com ela, o snapshot precisa de `ferroada.policy.sig` válida |
| `FERROADA_POLICY_SIG` | `ferroada.policy.sig` | Assinatura Ed25519 do snapshot (`ferroada policy compile`) |
| `FERROADA_PID_FILE` | `ferroada.pid` | Gravado no boot; `ferroada reload --pid-file` lê daqui |
| `TRUSTED_PROXIES` | *(vazio)* | CIDRs autorizados a enviar XFF/X-Forwarded-Proto |
| `SECURITY_HEADERS` | `true` | Injetar headers seguros nas respostas (nosniff, X-Frame, Referrer) |
| `FRAME_OPTIONS` | `SAMEORIGIN` | Valor de X-Frame-Options; `off` preserva o upstream |
| `CSP_POLICY` | *(desativada)* | Content-Security-Policy — só ative sabendo o que está fazendo |
| `PERMISSIONS_POLICY` | *(desativada)* | Permissions-Policy — só ative se não usar câmera/mic/geolocalização |
| `ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS` | Métodos HTTP permitidos |
| `MAX_BODY_SIZE` | `65536` | Tamanho máximo do body; valores maiores são limitados a 64KB pelo replay seguro do Pingora 0.8.1. Rotas com `max_decoded_body` usam esse teto no lugar. |
| `SPOOL_DIR` | *(unset = off)* | Diretório de spool; só é validado/limpo se alguma rota tem `max_decoded_body`. Default nesse modo: `/var/lib/ferroada/spool` |
| `SPOOL_MAX_BYTES` | `536870912` | Teto agregado de bytes de spool (512 MiB) |
| `SPOOL_MAX_FILES` | `256` | Teto de ficheiros `spool-*` simultâneos |
| `WAF_MAX_IN_FLIGHT_BYTES` | `67108864` | Reserva global para a cópia local, o replay do Pingora e o buffer de inspeção descompactada (256 KiB + byte sentinela) |
| `MAX_URI_LENGTH` | `8192` | Tamanho máximo da URI em bytes (8KB) |
| `ALLOWED_HOSTS` | *(desativada)* | Allowlist de domínios no Host header (ex.: `meusite.com,www.meusite.com`) |
| `FORCE_HTTPS` | `false` | Redirecionar HTTP → HTTPS (requer TLS configurado) |
| `HTTPS_REDIRECT_HOST` | *(vazio)* | Host público confiável para redirect no modo single-site/default |
| `DLP_ENABLED` | `true` | Liga a inspeção DLP de CPF/CNPJ/cartão e tokens nas respostas |
| `DLP_ACTION` | `redact` se unset e `DLP_ENABLED=true` | `monitor` (conta, não mascara), `redact` (mascara), `block` (502 se achar PII ou o buffer estourar). Packs de produção emitem `monitor` |
| `ORIGIN_SECRET_HEADER` | `X-Ferroada-Origin` se só `ORIGIN_SECRET` existir | Nome do header injetado no upstream. Unset com secret vazio = não injeta |
| `ORIGIN_SECRET` | *(unset)* | Valor do header de origem. Nunca logado. Vazio = não injeta |
| `DLP_MAX_RESPONSE_BYTES` | `1048576` | Buffer máximo por resposta textual inspecionada pelo DLP |
| `DLP_MAX_IN_FLIGHT_BYTES` | `67108864` | Budget global de memória para buffers DLP simultâneos |
| `BAD_BOT_ENABLED` | `true` | Bloqueio por assinatura de User-Agent (sqlmap, nikto, ...) |
| `WAF_PROFILE` | `generic` | `generic`, `wordpress` (monitor) ou `strict` para paths operacionais do WordPress |
| `WAF_REQUIRE_COMPLETE_PATHS` | *(vazio)* | Prefixos fail-closed no modo single-site, separados por vírgula |
| `WAF_ENGINE` | `native` | `native` (só L0) ou `coraza` (L1 sidecar; exige Unix socket e ready probe) |
| `WAF_SIDECAR_SOCKET` | `/run/coraza/waf.sock` | Socket do sidecar L1 |
| `WAF_SIDECAR_TIMEOUT_MS` | `500` | Teto da chamada L1. 20 ms devolveria 403 em tráfego limpo no cold start do CRS |
| `BEHAVIORAL_ENABLED` | `true` | Score de comportamento por site/rede |
| `BEHAVIORAL_SLOW_THRESHOLD` | `50` | Pontos para começar a frear o IP |
| `BEHAVIORAL_BLOCK_THRESHOLD` | `80` | Pontos para banir o IP |
| `BEHAVIORAL_BAN_SECS` | `600` | Duração do ban em segundos |
| `BEHAVIORAL_MAX_IPS` | `50000` | Teto de IPs rastreados (limpeza LRU acima disso) |

*\* `TARGET_URL` é obrigatória apenas no modo single-site. No modo multi-site, use o `ferroada.toml`.*

### Multi-site

Para proteger vários backends com um único deploy, crie um arquivo `ferroada.toml`:

```toml
# Backend padrão para hosts não configurados (opcional)
# default_backend = "http://fallback:8080"

[[sites]]
hosts = ["meusite.com", "www.meusite.com"]
backend = "http://backend-a:8080"
# backend = ["http://a:8080", "http://b:8080"]  # round-robin + health GET /health/ready
waf_profile = "wordpress"
require_complete_waf_inspection = ["/api/payment", "/api/admin/"]

[[sites]]
hosts = ["api.meusite.com"]
backend = "http://backend-b:3000"

[[sites]]
hosts = ["outrosite.com", "www.outrosite.com"]
backend = "https://backend-c:443"
```

O roteamento é feito automaticamente pelo Host header de cada request. Hosts não
configurados recebem `421 Misdirected Request`.

**Regras:**
- Se o `ferroada.toml` existe → modo multi-site (ignora `TARGET_URL`)
- Se não existe → usa `TARGET_URL` como antes (backward compatible)
- Rate limit e behavioral são isolados por site; IPv6 é agregado por /64
- WAF/DLP não mantêm decisões entre sites; métricas continuam globais ao processo
- A env `ALLOWED_HOSTS` continua funcionando como restrição adicional

```bash
# Multi-site com Docker (laboratório). Produção: deploy/topologies/
docker run -d \
  -v ./ferroada.toml:/ferroada.toml:ro \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -p 3000:3000 \
  ferroada
```

### HTTPS (TLS termination)

Para produção, configure TLS para aceitar HTTPS na porta 3443:

```bash
docker run -d \
  -e TARGET_URL=http://backend:8080 \
  -e TLS_CERT_PATH=/certs/fullchain.pem \
  -e TLS_KEY_PATH=/certs/privkey.pem \
  -e DASHBOARD_BIND=127.0.0.1 \
  -e DASHBOARD_TOKEN='troque-por-um-token-longo' \
  -v /etc/letsencrypt/live/meudominio:/certs:ro \
  -p 443:3443 \
  -p 80:3000 \
  ferroada
```

---

## Integração com sistemas existentes

### Docker Compose (single-site)

```yaml
services:
  ferroada:
    build: ./ferroada
    ports:
      - "80:3000"
    environment:
      - TARGET_URL=http://app:8080
      - RATE_LIMIT_MAX=100
      - DASHBOARD_BIND=127.0.0.1
      - DASHBOARD_TOKEN=${FERROADA_DASHBOARD_TOKEN}
    depends_on:
      - app

  app:
    image: seu-sistema:latest
    expose:
      - "8080"
```

O dashboard não se publica na internet. Túnel: `ssh -L 9000:127.0.0.1:9000`. Nos packs Docker o mapa é só `127.0.0.1:9000` no anfitrião. Packs completos: `deploy/topologies/`.

### Docker Compose (multi-site)

```yaml
services:
  ferroada:
    build: ./ferroada
    ports:
      - "80:3000"
    environment:
      - DASHBOARD_BIND=127.0.0.1
      - DASHBOARD_TOKEN=${FERROADA_DASHBOARD_TOKEN}
    volumes:
      - ./ferroada.toml:/ferroada.toml:ro
    depends_on:
      - site-a
      - site-b

  site-a:
    image: meusite:latest
    expose:
      - "8080"

  site-b:
    image: outrosite:latest
    expose:
      - "3000"
```

### Nginx (apontar para o Ferroada)

```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Configure `TRUSTED_PROXIES` com o CIDR real da rede do Nginx. Sem isso, o
Ferroada ignora XFF e usa o socket remoto. Um peer fora dessa allowlist não
consegue trocar de identidade enviando headers próprios.

### AWS / Cloud

Aponte o ALB/Target Group para a porta 3000 do container Ferroada em vez do
backend direto.

### Produção atrás de uma borda

O desenho recomendado é `Internet → Cloudflare/CDN/LB → Ferroada → backend`.
DDoS fica no CDN. Quem olha a request da sua API é o Ferroada, no seu servidor.
Restrinja a origem para aceitar somente a borda (firewall, tunnel privado ou
mTLS) e cadastre os CIDRs dela em `TRUSTED_PROXIES`. O Ferroada não substitui
Anycast nem mitigação DDoS L3/L4: se o link da máquina saturar, o processo não
tem como responder 429.

O estado continua local a cada réplica. Em múltiplas réplicas, configure
`REPLICA_COUNT`: o Ferroada divide os budgets de rate e os thresholds de
comportamento para manter o limite agregado conservador mesmo sem store. Bans e
histórico não são replicados; mantenha afinidade por cliente ou aplique a camada
distribuída na borda. Logs saem em stdout para o coletor da plataforma.
`GET /healthz` confirma o processo; `GET /readyz` testa os backends com deadline
e retorna 503 se algum estiver indisponível. Essas rotas não exigem token;
`/api/metrics` e `/metrics` usam a autenticação do dashboard.

---

## Arquitetura

```
src/
├── lib.rs           # Biblioteca compartilhada pelo binário, testes e fuzzing
├── main.rs          # Bootstrap: server, TLS, dashboard
├── client_ip.rs     # Trusted proxies e identidade por site/rede/rota/sessão/API key
├── config.rs        # Multi-site (ferroada.toml) ou single-site (TARGET_URL)
├── proxy.rs         # ProxyHttp: pipeline HTTPS → Host → Route → Method → Size → Rate Limit → Behavioral → WAF (todos os chunks, gzip) → Upstream (com timeout) → Headers → DLP
├── waf.rs           # WAF: SQLi + XSS + Path Traversal + CRLF + JNDI + Smuggling + Sensitive Paths + body gzip/deflate + decode 8x + headers
├── behavioral.rs    # Score por site/rede: scoring, decay, ban, LRU e testes
├── headers.rs       # Injeção de security headers + remoção de headers de servidor
├── shield.rs        # Restrição de métodos + limites de tamanho + validação de Host + bad bots
├── dlp.rs           # DLP: identity/gzip/deflate, limites e integridade de headers
├── graphql.rs       # GraphQL AST: profundidade, aliases, fragments, batch, introspection
├── grpc.rs          # gRPC: FileDescriptorSet, allowlist de método, tamanho de frame, reflection
├── rate_limit.rs    # Sliding window isolado por site/rede, evicção e teto de chaves
├── metrics.rs       # Contadores atômicos + ring buffer de eventos
└── dashboard.rs     # API JSON /api/metrics + HTML mínimo
web/                 # Painel Next.js (preto e branco)
fuzz/                # Harnesses cargo-fuzz para WAF, parser HTTP/1, frames HTTP/2, smuggling, buffers por chunks e DLP
```

### Pipeline de request

```
Cliente
  │
  ▼
[HTTPS Redirect] ──301──→ Cliente (se FORCE_HTTPS e request HTTP)
  │ ok
  ▼
[Host Check] ──421──→ Cliente (Host não permitido, DNS rebinding)
  │ ok
  ▼
[Route Backend] ──421──→ Cliente (Host sem site configurado, multi-site)
  │ ok
  ▼
[Method Check] ──405──→ Cliente (TRACE, CONNECT, etc.)
  │ ok
  ▼
[Size Check] ──413/414──→ Cliente (body/URI grande demais)
  │ ok
  ▼
[Rate Limiter] ──429──→ Cliente (Too Many Requests)
  │ ok
  ▼
[Behavioral Score] ──403──→ Cliente (IP acima do threshold de ban)
  │ ok
  ▼
[WAF: Sensitive Paths] ──403──→ Cliente (Access Denied)
  │ ok
  ▼
[WAF: URI + Headers] ──403──→ Cliente (SQLi/XSS/Traversal/CRLF/JNDI) [com double-decode]
  │ ok
  ▼
[WAF: Body Inspection] ──403──→ Cliente (injeção no body)
  │ ok
  ▼
[Upstream Backend]
  │
  ▼
[Strip Server Headers] → Remove Server, X-Powered-By, etc.
  │
  ▼
[Inject Security Headers] → HSTS, CSP, X-Frame-Options, etc.
  │
  ▼
[DLP: Response Masking] → CPF/CNPJ/cartão e tokens mascarados
  │
  ▼
Cliente (resposta limpa e hardened)
```

---

## Stack

- **Pingora 0.8** (Cloudflare) — proxy HTTP de alta performance
- **Rust** — binário único, sem runtime, sem garbage collector
- **Distroless** — imagem Docker sem shell, sem package manager (~20MB)
- **Zero dependências externas** — não precisa de Redis, banco de dados nem serviço auxiliar
