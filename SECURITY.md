# Política de segurança

O Ferroada **não** é production-grade. Falta auditoria de segurança externa
e não há linha LTS. Tratar o binário como “pronto para produção global”
depende dessas duas coisas, não deste ficheiro.

`SMAUG_AUDIT.md` (2026-08-31) é revisão interna do repositório. Não substitui
auditoria externa.

## Como reportar uma falha

Não abra issue pública com PoC, payload ou passos que permitam explorar.

1. Use o [relatório privado de vulnerabilidade do GitHub](https://github.com/DenisCDev/ferroada/security/advisories/new) neste repositório.
2. Inclua: versão ou commit, configuração relevante (**sem** segredos), passos para reproduzir, impacto esperado.
3. Se o formulário privado não estiver activo, contacte o maintainer por mensagem privada no GitHub. Não publique o exploit.

Não há CNA neste projecto, não atribuímos CVE, e não há bug bounty.

## Prazos internos

Metas de trabalho, não SLA contratual e não janela LTS. Um atraso não torna
o produto production-grade.

| Severidade | O que conta | Primeira resposta | Correção visada |
| --- | --- | --- | --- |
| Crítica | RCE no proxy, bypass total do WAF em rota fail-closed, leak de token/dashboard | 2 dias úteis | 7 dias úteis |
| Alta | Bypass parcial, DoS no data plane, leak de PII que o DLP deveria parar | 5 dias úteis | 14 dias úteis |
| Média | Falha que exige config insegura do operador, ou impacto limitado | 10 dias úteis | 30 dias úteis |
| Baixa | Hardening, disclosure menor, dívida de dependência transitiva | 15 dias úteis | próximo ciclo |

“Correção visada” é o patch na `main` (ou o workaround documentado). Versões
antigas **não** têm janela de patch.

## O que isto ainda não é

- Sem auditoria de segurança externa.
- Sem linha LTS: só a `main` e a última tag, se existir, recebem correção.
- Sem CNA, sem atribuição de CVE daqui, sem programa de recompensa.
- Sem operator Kubernetes, sem OIDC/mTLS no dashboard.
- A imagem de CI **não** é publicada nem assinada: este repositório não tem
  registry do Ferroada (nem GHCR, nem Docker Hub). Cosign keyless (OIDC do
  GitHub Actions, sem chave longa no repo) está documentado no job `docker`
  de `.github/workflows/security.yml` para quando houver registry. Até lá,
  o job constrói `ferroada:ci` localmente e para.

## O que já existe (sem vender como selo)

- `cargo audit --deny warnings` no `Dockerfile` e no job `rust` do CI.
  Exceções transitivas do Pingora 0.8.1 estão em `.cargo/audit.toml`.
- Fuzz `waf`, `protocol` e `dlp` no CI de pull request (tempo curto por alvo).
- SBOM CycloneDX do crate `ferroada` como **artefacto** de CI, não commitado
  no git.
