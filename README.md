# Ferroada — Reverse Proxy de Seguranca de Infraestrutura

Ferroada e um proxy reverso de seguranca que fica **na frente** do seu sistema existente, sem precisar alterar uma linha de codigo. Ele intercepta o trafego HTTP, bloqueia ataques conhecidos na entrada e mascara dados sensiveis na saida.

Construido com [Pingora](https://github.com/cloudflare/pingora) (Cloudflare), compilado para um unico binario, distribuido como container Docker distroless (~20MB).

```
Internet → [Ferroada :3000] → Seu Sistema :8080
                ↓
         Dashboard :9000
```

---

## O que o Ferroada protege

### Camada de Entrada (WAF)

| Ataque | Onde inspeciona | Exemplo bloqueado |
|--------|----------------|-------------------|
| **SQL Injection** | URI, headers, body (POST/PUT/PATCH) | `?id=1 UNION SELECT * FROM users` |
| **XSS (Cross-Site Scripting)** | URI, headers, body (POST/PUT/PATCH) | `<script>alert(1)</script>`, `onerror=`, `javascript:` |
| **Path Traversal** | URI, headers | `../../etc/passwd`, `%2e%2e%2f` |
| **Sensitive Path Access** | URI path | `/.env`, `/.git/`, `/wp-admin`, `/phpmyadmin`, `/.aws/credentials` |
| **Brute Force / DDoS basico** | IP de origem | Sliding window rate limit por IP (config via env) |

#### Paths bloqueados por padrao

Arquivos e diretarios que nunca deveriam ser expostos publicamente:

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

#### Inspecao de Body (POST/PUT/PATCH)

Formularios, APIs JSON e qualquer payload enviado via POST, PUT ou PATCH e inspecionado para SQL Injection e XSS antes de chegar ao seu backend. Limitado aos primeiros 64KB do body para evitar impacto de performance em uploads grandes.

### Hardening de Infraestrutura (v0.3)

| Protecao | O que faz | Resposta |
|----------|-----------|----------|
| **Security Headers** | Injeta X-Content-Type-Options, X-Frame-Options, Referrer-Policy em toda resposta | Headers automaticos |
| **Server Header Stripping** | Remove `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Debug-Token`, `X-Runtime` | Informacao de infra oculta |
| **HTTP Method Restriction** | Bloqueia TRACE, CONNECT e metodos nao configurados | 405 Method Not Allowed |
| **Request Size Limiting** | Limita tamanho do body (10MB default) e URI (8KB default) | 413 / 414 |
| **Host Validation** | Valida Host header contra allowlist `ALLOWED_HOSTS` (previne DNS rebinding) | 421 Misdirected Request |
| **HTTPS Enforcement** | Redireciona HTTP → HTTPS quando TLS esta configurado + injeta HSTS | 301 Moved Permanently |
| **Dashboard Auth** | Protege dashboard com Bearer token quando `DASHBOARD_TOKEN` esta definido | 401 Unauthorized |
| **Double-encoding Protection** | Decodifica URL recursivamente (max 3x) antes do WAF | Previne bypass `%252e%252e` |
| **Dependency Audit** | `cargo audit` roda no Docker build — falha se houver crate com CVE conhecida | Build falha |

#### Security Headers — filosofia "nao quebrar"

**Sempre ligados** (zero risco de quebrar sites):
```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
X-XSS-Protection: 0
```

**Condicionais** (so ativam quando voce explicitamente configura):
```
Strict-Transport-Security    → so quando FORCE_HTTPS=true
Content-Security-Policy      → so quando CSP_POLICY esta definido
Permissions-Policy           → so quando PERMISSIONS_POLICY esta definido
```

**Removidos** da resposta (sempre):
```
Server, X-Powered-By, X-AspNet-Version, X-Debug-Token, X-Runtime
```

#### O que continua fora do escopo do proxy

| Vulnerabilidade | Por que nao da |
|----------------|----------------|
| Portas abertas no servidor | Firewall do OS (iptables/ufw) |
| Software desatualizado | Gerenciamento de pacotes do servidor |
| Permissoes de arquivo Linux | Configuracao do OS |
| Segmentacao de rede | Arquitetura de rede (VPC, firewalls) |
| Banco de dados exposto | Firewall + config do banco |

### Camada de Saida (DLP)

| Dado sensivel | Padrao detectado | Resultado mascarado |
|---------------|------------------|---------------------|
| **CPF** | `123.456.789-00` | `***.***.***-**` |
| **Bearer Token** | `Bearer eyJhbGciOi...` | `Bearer [REDACTED]` |

Se o seu backend vazar um CPF ou token na resposta, o cliente final nunca recebe o dado real.

### Monitoramento (Dashboard)

Dashboard web na porta 9000 com:
- Contadores em tempo real de cada tipo de bloqueio
- Ultimos 100 eventos de seguranca com timestamp, IP, URI e detalhes
- Auto-refresh a cada 5 segundos
- API JSON em `/api/metrics` para integracao com ferramentas externas

---

## O que o Ferroada NAO protege

Transparencia e importante. Estas vulnerabilidades sao de **logica de aplicacao** e precisam ser corrigidas no codigo do backend:

| Vulnerabilidade | Por que proxy nao resolve |
|----------------|--------------------------|
| **IDOR** (Insecure Direct Object Reference) | So o backend sabe se user A pode acessar recurso de user B |
| **Mass Assignment** | So o backend sabe quais campos sao permitidos em cada request |
| **Race Condition** | Controle de concorrencia e responsabilidade do banco/backend |
| **JWT / Secret fraco** | Configuracao de autenticacao do backend |
| **Senha em texto puro / hash sem salt** | Decisao de armazenamento no banco de dados |
| **Manipulacao de roles** | Autorizacao e logica de negocio do backend |
| **Engenharia social** | Fator humano — nenhum software resolve |
| **Game hacking / WebSocket** | Ferroada nao inspeciona trafego WebSocket |

**Ferroada e a primeira linha de defesa (infraestrutura), nao a unica.** Para seguranca completa, o backend precisa implementar validacao propria.

---

## Quick Start

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

# Rate limit → 429 (apos 100 requests)
for i in $(seq 1 105); do
  curl -s -o /dev/null -w "%{http_code} " http://localhost:3000/
done

# Dashboard
curl http://localhost:9000/api/metrics
# Ou abra http://localhost:9000 no navegador
```

---

## Configuracao

Todas as configuracoes sao via variaveis de ambiente:

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `TARGET_URL` | *(obrigatorio)* | URL do sistema upstream (ex: `http://meu-sistema:8080`) |
| `RUST_LOG` | `info` | Nivel de log (`debug`, `info`, `warn`, `error`) |
| `RATE_LIMIT_MAX` | `100` | Maximo de requests por IP na janela |
| `RATE_LIMIT_WINDOW` | `60` | Janela de tempo em segundos |
| `TLS_CERT_PATH` | *(opcional)* | Caminho para certificado TLS (fullchain.pem) |
| `TLS_KEY_PATH` | *(opcional)* | Caminho para chave privada TLS |
| `DASHBOARD_PORT` | `9000` | Porta do dashboard de monitoramento |
| `SECURITY_HEADERS` | `true` | Injetar headers seguros nas respostas (nosniff, X-Frame, Referrer) |
| `CSP_POLICY` | *(desativado)* | Content-Security-Policy — so ativar se souber o que esta fazendo |
| `PERMISSIONS_POLICY` | *(desativado)* | Permissions-Policy — so ativar se nao usar camera/mic/geo |
| `ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS` | Metodos HTTP permitidos |
| `MAX_BODY_SIZE` | `10485760` | Tamanho maximo do body em bytes (10MB) |
| `MAX_URI_LENGTH` | `8192` | Tamanho maximo da URI em bytes (8KB) |
| `ALLOWED_HOSTS` | *(desativado)* | Allowlist de dominios no Host header (ex: `meusite.com,www.meusite.com`) |
| `FORCE_HTTPS` | `false` | Redirecionar HTTP → HTTPS (requer TLS configurado) |
| `DASHBOARD_TOKEN` | *(vazio)* | Token Bearer para proteger o dashboard |

### HTTPS (TLS Termination)

Para producao, configure TLS para aceitar HTTPS na porta 3443:

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

## Integracao com sistemas existentes

### Docker Compose

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

### Nginx (apontar para Ferroada)

```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### AWS / Cloud

Aponte o ALB/Target Group para a porta 3000 do container Ferroada em vez do backend direto.

---

## Arquitetura

```
src/
├── main.rs          # Bootstrap: server, TLS, dashboard, env config
├── proxy.rs         # ProxyHttp: pipeline HTTPS → Host → Method → Size → Rate Limit → WAF → Upstream → Headers → DLP
├── waf.rs           # WAF: SQLi + XSS + Path Traversal + Sensitive Paths + Body Inspection + double-decode
├── headers.rs       # Security headers injection + server header stripping
├── shield.rs        # HTTP method restriction + request size limiting + host validation
├── dlp.rs           # DLP: CPF + Bearer Token masking nas respostas
├── rate_limit.rs    # Sliding window rate limiter por IP (DashMap)
├── metrics.rs       # Contadores atomicos + ring buffer de eventos
└── dashboard.rs     # Dashboard HTML + API JSON (/api/metrics) + token auth
```

### Pipeline de request (v0.3)

```
Cliente
  │
  ▼
[HTTPS Redirect] ──301──→ Cliente (se FORCE_HTTPS e request HTTP)
  │ ok
  ▼
[Host Check] ──421──→ Cliente (Host nao permitido, DNS rebinding)
  │ ok
  ▼
[Method Check] ──405──→ Cliente (TRACE, CONNECT, etc.)
  │ ok
  ▼
[Size Check] ──413/414──→ Cliente (body/URI muito grande)
  │ ok
  ▼
[Rate Limiter] ──429──→ Cliente (Too Many Requests)
  │ ok
  ▼
[WAF: Sensitive Paths] ──403──→ Cliente (Access Denied)
  │ ok
  ▼
[WAF: URI + Headers] ──403──→ Cliente (SQLi/XSS/Traversal) [com double-decode]
  │ ok
  ▼
[WAF: Body Inspection] ──403──→ Cliente (SQLi/XSS in body)
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
- **Rust** — binario unico, sem runtime, sem garbage collector
- **Distroless** — imagem Docker sem shell, sem package manager (~20MB)
- **Zero dependencias externas** — nao precisa de Redis, banco de dados ou servico auxiliar
