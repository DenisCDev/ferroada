# Auditoria Smaug

Data: 2026-08-31  
Escopo: repositório completo (`src/`, `web/`, manifests, imagem e CI)  
Status: sem achados abertos

## Achados resolvidos

| Severidade | Achado | Correção e evidência |
| --- | --- | --- |
| Crítica | O painel usava Next.js 16.3.2, afetado por avisos de segurança publicados para versões anteriores à 16.3.3. | Dependência e lock fixados em 16.3.3 (`web/package.json`); `npm audit --audit-level=high` sem vulnerabilidades. |
| Alta | O parser do Pingora normalizava headers de framing antes do filtro e podia ocultar combinações `Content-Length` + `Transfer-Encoding` ou linhas TE duplicadas. | O filtro agora conta CL e TE no bloco HTTP/1 bruto antes da normalização (`src/proxy.rs`, `raw_framing_header_counts`); os dois testes de socket retornaram 400 e zero requisições ao backend. |
| Média | A reserva global do WAF contabilizava apenas a cópia local do body. | A reserva cobre a cópia local, o replay do Pingora e o buffer fixo de inspeção descompactada, inclusive o byte sentinela (`src/proxy.rs`, `request_inspection_reservation`; `src/waf.rs`, `max_inflate_buffer_bytes`). |
| Baixa | Avisos RustSec transitivos eram informativos e não faziam a auditoria falhar. | A imagem e o CI usam `cargo audit --deny warnings`; cada exceção inevitável do Pingora 0.8.1 está identificada e justificada em `.cargo/audit.toml`. |
| Baixa | Uma mensagem do painel expunha o nome do framework em vez de orientar a operação. | A mensagem agora identifica o servidor do painel em pt-BR; o gate Smaug passou em todo o repositório. |

## Dimensões verificadas

- Segurança e segredos: busca no histórico e na árvore de trabalho sem credenciais; dashboard externo falha fechado sem token (`src/dashboard.rs`, `validate_exposure`).
- Origem de cliente: `X-Forwarded-For` só é aceito de proxies configurados e a cadeia é resolvida da direita para a esquerda (`src/client_ip.rs`).
- Recursos e rede: conexões, concorrência, buffers, decomposição e chamadas de upstream possuem limites ou deadlines (`src/connection.rs`, `src/proxy.rs`, `src/dlp.rs`).
- Banco e RLS: não aplicável; a busca no repositório não encontrou SQL, migrations nem integração Supabase.
- UI e fluxos: token permanece em `sessionStorage`, estados 401/503/indisponível são explícitos e há estado vazio (`web/src/components/Dashboard.tsx`).
- Código morto e erros: `cargo clippy --all-targets --all-features -- -D warnings`, build TypeScript e buscas de padrões proibidos sem falhas.

## Exceções transitivas acompanhadas

`protobuf`, `daemonize`, `derivative`, `proc-macro-error2` e `lru` vêm do Pingora 0.8.1. O arquivo `.cargo/audit.toml` documenta alcance, mitigação e condição de remoção. O CI rejeita qualquer aviso novo que não esteja explicitamente inventariado.

smaug: no findings. The hoard is accounted for.
