# Sidecar Coraza (WAF L1)

Camada opcional. O proxy Ferroada continua com o WAF regex (L0) sempre ligado.
Este processo fala CRS 4.25 LTS no Unix socket; um crash ou loop no ruleset
não mata o data plane.

O crate `ferroada` **não** depende de Coraza. `cargo tree -p ferroada` não
lista o motor.

## Subir

Na raiz do repositório, com um pack de topologia:

```bash
# no .env do pack
WAF_ENGINE=coraza
WAF_SIDECAR_SOCKET=/run/coraza/waf.sock
WAF_SIDECAR_TIMEOUT_MS=500

docker compose -f deploy/topologies/vps-api/docker-compose.yml \
  -f deploy/coraza/docker-compose.yml --profile coraza up -d --build
```

O proxy só marca o engine `coraza` depois do ready probe (`GET /readyz`).
Se o sidecar não responder, o processo recusa arrancar — não cai em L0
em silêncio.

Timeout e queda do sidecar no pedido: `InspectionOutcome::TimedOut`, métrica
`waf_engine_unavailable`, e a política da rota (`require_complete` → 403).

## Contrato HTTP no socket

- `GET /readyz` → 200 quando o CRS carregou
- `POST /inspect` corpo JSON `{ method, uri, protocol, headers, body_b64, client_ip, policy }`
  → `{ "action": "allow"|"deny", "rule_ids": [942100], "score": 15, "msg": "..." }`

`policy` (opcional): `blocking_paranoia` (1–4), `executing_paranoia` (1–4, ≥ blocking),
`anomaly_score_threshold` (default 5), `exclude_parameters`. Executing ≠ blocking:
regras do nível executing correm; só o blocking entra no score que decide o deny.

No TOML do proxy:

```toml
[waf.l1]
blocking_paranoia = 1
executing_paranoia = 4
shadow = true
anomaly_score_threshold = 5

[[sites]]
hosts = ["api.exemplo.com"]
backend = "http://app:8080"

[[sites.l1.exclusions]]
prefix = "/login"

[[sites.l1.exclusions]]
parameters = ["password", "token"]

[[sites.l1.exclusions]]
content_types = ["application/octet-stream"]
```

Shadow: o sidecar avalia, o proxy grava rule ID + score em `waf_l1_shadow` e
responde 200. A mesma regra com `shadow = false` responde 403. Timeout e
sidecar down continuam `TimedOut` + fail_closed — shadow não abre o WAF.
