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
- `POST /inspect` corpo JSON `{ method, uri, protocol, headers, body_b64, client_ip }`
  → `{ "action": "allow" }` ou `{ "action": "deny", "rule_ids": [942100], "msg": "..." }`

Paranoia, shadow e exclusão por rota são o PR 12 — não estão aqui.
