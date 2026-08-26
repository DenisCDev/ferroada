<h1 align="center">Ferroada</h1>

<p align="center">
  <b>Proxy reverso que filtra ataques conhecidos, mascara dados sensíveis e registra eventos</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-pingora%200.8-D4A24E?labelColor=171310" alt="Rust com Pingora 0.8">
  <img src="https://img.shields.io/badge/bin%C3%A1rio%20%C3%BAnico-distroless%20~20MB-43A48E?labelColor=171310" alt="binário único, container distroless de ~20MB">
  <img src="https://img.shields.io/badge/servi%C3%A7os%20externos-n%C3%A3o%20exige-43A48E?labelColor=171310" alt="não exige serviços externos">
  <img src="https://img.shields.io/badge/cargo%20audit-no%20build-D4A24E?labelColor=171310" alt="cargo audit roda no build">
</p>

<p align="center">
  <img src="assets/mtg-sting.jpg" width="640" alt="Ferroada, o Punhal Reluzente — arte de Nino Is, Tales of Middle-earth (2023)">
</p>

<p align="center">
  <sub><i>"I shall call you Sting"</i><br>
  — <b>O Hobbit</b>, capítulo VIII · arte de Nino Is para Magic: The Gathering, Tales of Middle-earth (2023)
</p>

O Ferroada fica entre a internet e uma aplicação existente. Ele inspeciona
requisições, bloqueia padrões conhecidos de ataque, limita tráfego por endereço
IP e mascara dados sensíveis em respostas. Os eventos aparecem em um painel e
em logs estruturados, sem exigir mudanças no código da aplicação protegida.

Ele complementa a segurança do backend; não substitui autenticação, autorização
ou validação dentro da aplicação. O proxy é construído em Rust com
[Pingora](https://github.com/cloudflare/pingora), distribuído como um binário
único e em uma imagem distroless de cerca de 20 MB.

```
Internet → [Ferroada :3000] → Seu Sistema :8080
                ↓
         Dashboard :9000
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
    Dashboard :9000
```

---

## O que o Ferroada protege

### Camada de entrada (WAF)

| Ataque | Onde inspeciona | Exemplo bloqueado |
|--------|----------------|-------------------|
| **SQL Injection** | URI, headers, body (POST/PUT/PATCH) | `?id=1 UNION SELECT * FROM users` |
| **XSS (Cross-Site Scripting)** | URI, headers, body (POST/PUT/PATCH) | `<script>alert(1)</script>`, `onerror=`, `javascript:` |
| **Path Traversal** | URI, headers | `../../etc/passwd`, `%2e%2e%2f` |
| **CRLF Injection** | URI, headers, body | `%0d%0aSet-Cookie:` (com skip de multipart no body) |
| **JNDI / Log4Shell** | URI, headers, body | `${jndi:ldap://...}`, inclusive ofuscado |
| **Request Smuggling** | Headers | `Content-Length` duplicado, `CL`+`TE`, `TE` inválido → 400 |
| **Sensitive Path Access** | URI path | `/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`, `/.aws/credentials` |
| **Bad Bots** | User-Agent | 18 assinaturas: sqlmap, nikto, nuclei, etc. |
| **Brute Force / DDoS básico** | IP de origem | Rate limit sliding window por IP (config via env) |

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
/wp-admin/  /wp-login.php  /wp-config.php  /xmlrpc.php
/phpmyadmin/  /phpinfo.php  /server-status  /server-info
/actuator/  /console  /debug
/config.php  /config.yml  /config.json  /database.yml
/docker-compose.yml  /Dockerfile  /.dockerenv
/.ssh/  /id_rsa  /id_ed25519  /.aws/credentials
/.bash_history  /.npmrc  /.vscode  /.idea  /web.config
```

#### Inspeção de body (POST/PUT/PATCH)

Formulários, APIs JSON e qualquer payload enviado via POST, PUT ou PATCH são
inspecionados antes de chegar ao backend. O proxy lê **todos** os chunks do
body (não só o primeiro), aplica o teto de `MAX_BODY_SIZE` também em
`Transfer-Encoding: chunked`, e se o cliente mandou `Content-Encoding: gzip`
ou `deflate` o WAF infla uma cópia só para inspecionar — o bytes originais
seguem para o upstream. A inspeção em si olha os primeiros 64KB do texto
(inflado, se for o caso) para não penalizar uploads grandes. Um gzip
gigante é cortado em 256KB inflados, então um zip bomb não estoura a memória.

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

Cruzou 50 pontos, o IP é freado; cruzou 80, é banido por 10 minutos. Os
thresholds são configuráveis, o tracking tem teto de 50 mil IPs com limpeza
LRU, e a lógica de decay, scoring e ban tem testes unitários
(`src/behavioral.rs`).

### Hardening de infraestrutura

| Proteção | O que faz | Resposta |
|----------|-----------|----------|
| **Security Headers** | Injeta X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-Permitted-Cross-Domain-Policies em toda resposta | Headers automáticos |
| **Server Header Stripping** | Remove `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-Token`, `X-Runtime` | Informação de infra oculta |
| **HTTP Method Restriction** | Bloqueia TRACE, CONNECT e métodos não configurados | 405 Method Not Allowed |
| **Request Size Limiting** | Limita tamanho do body (10MB default) e da URI (8KB default) | 413 / 414 |
| **Host Validation** | Valida o Host header contra a allowlist `ALLOWED_HOSTS` (previne DNS rebinding) | 421 Misdirected Request |
| **HTTPS Enforcement** | Redireciona HTTP → HTTPS quando TLS está configurado + injeta HSTS | 301 Moved Permanently |
| **Dashboard Auth** | Protege o dashboard com Bearer token quando `DASHBOARD_TOKEN` está definido | 401 Unauthorized |
| **Multi-encoding Protection** | Decodifica URL e headers recursivamente (máx. 8x), inclusive `%uXXXX` e `+` como espaço na query | Previne bypass `%2525252e`, XSS percent-encoded em header |
| **Upstream timeouts** | `HttpPeer` com connect/read/write; body do cliente tem deadline próprio | Upstream morto não segura o worker |
| **Rate limit com evicção** | Sliding window por IP; chaves expiradas saem do mapa; teto de IPs rastreados | Flood de IPs únicos não cresce a memória para sempre |
| **Dependency Audit** | `cargo audit` roda no build Docker — falha se houver crate com CVE conhecida | Build falha |

#### Security headers — filosofia "não quebrar"

**Sempre ligados** (zero risco de quebrar sites):
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 0
X-Permitted-Cross-Domain-Policies: none
```

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
| **CPF** | `123.456.789-00` | `***.***.***-**` |
| **Bearer Token** | `Bearer eyJhbGciOi...` | `Bearer [REDACTED]` |

Com `DLP_ENABLED=true`, respostas textuais em UTF-8 de até 50 MB têm CPF e
tokens conhecidos mascarados antes de chegar ao cliente. Respostas comprimidas
(por exemplo, com `Content-Encoding: gzip`) não são inspecionadas.

### Monitoramento

<p align="center">
  <img src="assets/dashboard.png" width="880" alt="Painel do Ferroada em preto e branco: visão geral com requisições, bloqueios, tráfego limpo e lista de eventos">
</p>

O binário serve JSON em `http://localhost:9000/api/metrics` e um HTML mínimo na mesma porta.

O painel Next (preto e branco, `web/`) é a interface: Visão geral e Eventos, atualização a cada 5 s. Se o proxy não estiver no ar, o painel mostra dados de demonstração.

```bash
cd web
npm install
npm run dev    # http://localhost:3100
```

`FERROADA_URL` (default `http://127.0.0.1:9000`) e `FERROADA_TOKEN` (se `DASHBOARD_TOKEN` estiver setado) ficam no servidor Next, não no browser.

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

### 1. Build

```bash
docker build -t ferroada .
```

### 2. Run

```bash
docker run -d \
  -e TARGET_URL=http://host.docker.internal:8080 \
  -e RUST_LOG=info \
  -e RATE_LIMIT_MAX=100 \
  -e RATE_LIMIT_WINDOW=60 \
  -p 3000:3000 \
  -p 9000:9000 \
  --name ferroada \
  ferroada
```

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

# Dashboard
curl http://localhost:9000/api/metrics
# Ou abra http://localhost:9000 no navegador
```

---

## Configuração

Toda a configuração é feita por variáveis de ambiente:

| Variável | Default | Descrição |
|----------|---------|-----------|
| `TARGET_URL` | *(obrigatória\*)* | URL do sistema upstream — modo single-site (ex.: `http://meu-sistema:8080`) |
| `RUST_LOG` | `info` | Nível de log (`debug`, `info`, `warn`, `error`) |
| `RATE_LIMIT_MAX` | `100` | Máximo de requests por IP na janela |
| `RATE_LIMIT_WINDOW` | `60` | Janela de tempo em segundos |
| `RATE_LIMIT_MAX_IPS` | `50000` | Teto de IPs no mapa (evicção LRU acima disso) |
| `UPSTREAM_CONNECT_TIMEOUT` | `5` | Segundos para o `connect()` no backend |
| `UPSTREAM_READ_TIMEOUT` | `30` | Segundos máximos lendo a resposta do backend |
| `UPSTREAM_WRITE_TIMEOUT` | `30` | Segundos máximos escrevendo no backend |
| `BODY_READ_TIMEOUT` | `10` | Segundos máximos lendo o body do cliente |
| `TLS_CERT_PATH` | *(opcional)* | Caminho para o certificado TLS (fullchain.pem) |
| `TLS_KEY_PATH` | *(opcional)* | Caminho para a chave privada TLS |
| `DASHBOARD_PORT` | `9000` | Porta do dashboard de monitoramento |
| `DASHBOARD_TOKEN` | *(vazio)* | Token Bearer para proteger o dashboard |
| `SECURITY_HEADERS` | `true` | Injetar headers seguros nas respostas (nosniff, X-Frame, Referrer) |
| `CSP_POLICY` | *(desativada)* | Content-Security-Policy — só ative sabendo o que está fazendo |
| `PERMISSIONS_POLICY` | *(desativada)* | Permissions-Policy — só ative se não usar câmera/mic/geolocalização |
| `ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS` | Métodos HTTP permitidos |
| `MAX_BODY_SIZE` | `10485760` | Tamanho máximo do body em bytes (10MB) |
| `MAX_URI_LENGTH` | `8192` | Tamanho máximo da URI em bytes (8KB) |
| `ALLOWED_HOSTS` | *(desativada)* | Allowlist de domínios no Host header (ex.: `meusite.com,www.meusite.com`) |
| `FORCE_HTTPS` | `false` | Redirecionar HTTP → HTTPS (requer TLS configurado) |
| `DLP_ENABLED` | `true` | Mascaramento de CPF e tokens nas respostas |
| `BAD_BOT_ENABLED` | `true` | Bloqueio por assinatura de User-Agent (sqlmap, nikto, ...) |
| `BEHAVIORAL_ENABLED` | `true` | Score de comportamento por IP |
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
- WAF, DLP, rate limit e security headers são compartilhados entre todos os sites
- A env `ALLOWED_HOSTS` continua funcionando como restrição adicional

```bash
# Multi-site com Docker
docker run -d \
  -v ./ferroada.toml:/ferroada.toml:ro \
  -p 3000:3000 \
  -p 9000:9000 \
  ferroada
```

### HTTPS (TLS termination)

Para produção, configure TLS para aceitar HTTPS na porta 3443:

```bash
docker run -d \
  -e TARGET_URL=http://backend:8080 \
  -e TLS_CERT_PATH=/certs/fullchain.pem \
  -e TLS_KEY_PATH=/certs/privkey.pem \
  -v /etc/letsencrypt/live/meudominio:/certs:ro \
  -p 443:3443 \
  -p 80:3000 \
  -p 9000:9000 \
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
      - "9000:9000"
    environment:
      - TARGET_URL=http://app:8080
      - RATE_LIMIT_MAX=100
    depends_on:
      - app

  app:
    image: seu-sistema:latest
    expose:
      - "8080"
```

### Docker Compose (multi-site)

```yaml
services:
  ferroada:
    build: ./ferroada
    ports:
      - "80:3000"
      - "9000:9000"
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

### AWS / Cloud

Aponte o ALB/Target Group para a porta 3000 do container Ferroada em vez do
backend direto.

---

## Arquitetura

```
src/
├── main.rs          # Bootstrap: server, TLS, dashboard
├── config.rs        # Multi-site (ferroada.toml) ou single-site (TARGET_URL)
├── proxy.rs         # ProxyHttp: pipeline HTTPS → Host → Route → Method → Size → Rate Limit → Behavioral → WAF (todos os chunks, gzip) → Upstream (com timeout) → Headers → DLP
├── waf.rs           # WAF: SQLi + XSS + Path Traversal + CRLF + JNDI + Smuggling + Sensitive Paths + body gzip/deflate + decode 8x + headers
├── behavioral.rs    # Score de comportamento por IP: scoring, decay, ban, LRU (com testes unitários)
├── headers.rs       # Injeção de security headers + remoção de headers de servidor
├── shield.rs        # Restrição de métodos + limites de tamanho + validação de Host + bad bots
├── dlp.rs           # DLP: mascaramento de CPF e Bearer Token nas respostas
├── rate_limit.rs    # Rate limiter sliding window por IP, evicção de janela vazia, teto de IPs (DashMap)
├── metrics.rs       # Contadores atômicos + ring buffer de eventos
└── dashboard.rs     # API JSON /api/metrics + HTML mínimo
web/                 # Painel Next.js (preto e branco)
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
[DLP: Response Masking] → CPF e tokens mascarados
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
