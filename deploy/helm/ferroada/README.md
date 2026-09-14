# Ferroada — chart Helm

Gateway de origem no Kubernetes. O pod corre rootless, o dashboard **não** é
Service nem Ingress, e o origin tem de recusar tudo que não seja o Ferroada.

Não substitui CDN nem DDoS L3/L4. Desenho: `Internet → [CDN] → Ferroada → origin`.

## O que este chart recusa

- Publicar a porta 9000. `dashboardBind` só aceita loopback (`127.0.0.1` /
  `::1`); `service.port=9000` é recusado. O NetworkPolicy só admite a porta
  do proxy (3000). Túnel: `kubectl port-forward deploy/<release> 9000:9000`.
- `WAF_ENGINE=coraza` por default. L1 é sidecar opt-in, não este chart.
- OTel ligado. `otelEndpoint` vazio = o processo não abre socket extra.
- Token vazio. `FERROADA_PRODUCTION=true` e o chart recusam arranque sem
  `ferroada.dashboardToken` (ou `existingSecret`).
- Probe com `curl`. A imagem é distroless; liveness/readiness correm
  `/ferroada healthcheck` (GET em `127.0.0.1:9000/healthz`, exit 0/1).

## Install

```bash
openssl rand -hex 32   # cole em ferroada.dashboardToken
helm upgrade --install ferroada deploy/helm/ferroada \
  --set ferroada.dashboardToken=<token> \
  --set ferroada.origin=http://app.default.svc:8080 \
  --set image.repository=ghcr.io/exemplo/ferroada \
  --set image.tag=0.6.0
```

Imagem: a mesma distroless do `Dockerfile` (`ferroada:0.6.0`). Apontar o
`repository` para o registry onde você publicou o build.

## Rolling e um replica sozinho

O default é `replicaCount: 1`. Rate limit e score de comportamento vivem na
**memória de cada pod**. Uma réplica sozinha é ponto único de falha: se o
pod morre, o tráfego para. O PDB com `maxUnavailable: 1` *permite* drenar
esse único pod — não inventa alta disponibilidade.

Rolling sem queda perceptível pede **pelo menos duas réplicas**:

```yaml
replicaCount: 2
```

O chart injeta `REPLICA_COUNT` igual ao `replicaCount`, para o processo
dividir os budgets. Não escale com HPA sem atualizar esse valor: três pods
com `REPLICA_COUNT=1` afrouxam o limite; um pod com `REPLICA_COUNT=3`
aperta demais.

A estratégia é `RollingUpdate` com `maxUnavailable: 0` e `maxSurge: 1`: o
pod novo fica Ready (`ferroada healthcheck`) antes do antigo sair. Com uma
réplica ainda há um instante com dois processos e estado duplicado — não é
HA, é só o surge.

## O origin só aceita o Ferroada

O Service deste chart é o único jeito público de chegar ao proxy. O backend
**não** ganha Service/Ingress neste chart. No cluster:

1. Origin sem `type: LoadBalancer` / NodePort / Ingress próprio.
2. NetworkPolicy (ou firewall) do origin: ingress só a partir dos pods
   `app.kubernetes.io/name=ferroada`.
3. Header `ORIGIN_SECRET` (`--set ferroada.originSecret=...`) e o origin a
   recusar pedidos sem ele.

Se o origin continua público, o Ferroada é um extra, não um gateway.

## Dashboard

Não há caminho HTTP de outro pod até `:9000`. Bind em loopback + NetworkPolicy
sem essa porta. Métricas: o mesmo túnel `port-forward`, Bearer
`DASHBOARD_TOKEN`.

## Probes e segurança do pod

| Campo | Default |
| --- | --- |
| `runAsNonRoot` | `true` (uid 65532, nonroot do distroless) |
| `readOnlyRootFilesystem` | `true` (`/tmp` em emptyDir) |
| `capabilities.drop` | `ALL` |
| `seccompProfile` | `RuntimeDefault` |
| liveness / readiness | `exec: ["/ferroada", "healthcheck"]` |

Filesystem só de leitura: o pid vai para `/tmp/ferroada.pid`. Spool é opt-in
(`spool.enabled`); sem `max_decoded_body` no TOML o processo ignora o
directório.

## Values que importam

| Key | Default | Nota |
| --- | --- | --- |
| `ferroada.dashboardBind` | `127.0.0.1` | Só loopback; outro valor recusa o template |
| `ferroada.origin` | `http://substitua-origin.invalid:8080` | DNS no boot; placeholder não colide com um Service `app` |
| `ferroada.dashboardToken` | placeholder | Obrigatório; use `existingSecret` em produção |
| `ferroada.wafEngine` | `native` | `coraza` só com sidecar L1 à parte |
| `ferroada.otelEndpoint` | `""` | Vazio = off |
| `ferroada.origin` | `http://app:8080` | Single-site (`TARGET_URL`) se `config.toml` vazio |
| `resources` | 100m/128Mi → 1 CPU/512Mi | Pedidos e limites sempre emitidos |
| `topologySpreadConstraints` | `[]` | Opt-in; o chart preenche o `labelSelector` |
| `networkPolicy.enabled` | `true` | Ingress só na porta do proxy |
| `ingress.enabled` | `false` | Se ligar, o backend é a porta 3000 |

TOML multi-site: `config.toml` (string) ou `config.existingConfigMap`. Não
monte um `ferroada.toml` vazio — o processo trata ficheiro presente como
multi-site e falha o parse.

## Fora deste chart

Operator Kubernetes, Terraform, SBOM/cosign, OIDC no admin. Packs systemd
estão em `deploy/topologies/` e não se misturam com este chart.
