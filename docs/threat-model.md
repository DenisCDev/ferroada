# Modelo de ameaça — matriz de protocolo

Nada cai em “permitir” silencioso. A linha ou é `inspect` (o L0 inspeciona de
verdade) ou uma das quatro ações de não-suportado: `deny`, `monitor`,
`bypass-explicit`, `route-to-quarantine`.

`route-to-quarantine` na v1 é a mesma resposta que `deny` (403) mais
`SecurityEvent.event_type = "quarantine"` e métrica `protocol_quarantine`.
Não há origin honeypot (Fase 7).

## Atores

| Ator | O que tenta | O que a matriz faz |
| --- | --- | --- |
| Cliente externo | HTTP/1.0, HTTP/3, gRPC, upgrade estranho, body que o L0 não parseia | Default deny ou monitor explícito; nunca inspect fingido |
| Outro tenant | Encher o ring de eventos / score com lixo de protocolo | Evento e métrica por id; isolamento de score/rate continua por site (não é este PR) |
| Edge comprometido | Protocolo que o origin não deveria ver (WS, h2c, HTTP/1.0) | Mesma matriz: o peer trusted não desliga o contrato |
| Backend malformado | Resposta SSE/gRPC/101 que o DLP não deve mutar | SSE/upgrade: bypass-explicit observável no DLP; gRPC no request já é deny |
| Control plane | Ainda não existe; a política é o TOML no disco | `[protocols]` versionado com o resto do ficheiro; chave `unknown` ambígua é erro de parse |
| Ruleset | WAF regex a tratar multipart como texto “completo” | Multipart v1 **não** é `inspect`; `require_complete` → deny |
| Plugin | Não há ABI de plugin neste crate | Residual: um plugin futuro não pode silenciar a matriz; ela corre no processo antes do L0 de body |
| Operador | Ligar `inspect` numa linha sem parser, ou `unknown = "deny"` | Parse recusa. `bypass-explicit` e `monitor` exigem evento |
| Dependência | Pingora aceitar HTTP/1.0 / Upgrade que o L0 não cobre | A matriz lê `http::Version` e o header `Upgrade` **depois** do parser, e decide |

## Matriz (default)

| Linha | Default | Se incompleto / não suportado | Teste |
| --- | --- | --- | --- |
| HTTP/1.0 | não suportado | `deny` → 403 | `http_1_0_default_deny_is_403` |
| HTTP/1.1 | `inspect` | — | `http_1_1_and_http_2_default_inspect` |
| HTTP/2 | `inspect` | — | `http_1_1_and_http_2_default_inspect` |
| HTTP/3 | não suportado (sem listener) | `deny` → 403 | `http_3_default_deny_is_403` |
| WebSocket / `Upgrade` | não suportado | `bypass-explicit` (evento `protocol_bypass`); `deny` se o operador trocar | `websocket_default_bypass_skips_body_waf`, `websocket_deny_is_403` |
| Upgrade desconhecido | não suportado | `deny` | `unknown_upgrade_default_deny_is_403` |
| SSE (request) | `inspect` | — | `gzip_json_and_sse_request_stay_inspect` |
| SSE (response) | n/a | `bypass-explicit` no DLP (skip observável já existente) | `dlp::streaming_response_is_not_buffered_for_dlp` |
| gRPC | não suportado | `deny` → 403 | `grpc_default_deny_is_403` |
| JSON | `inspect` | ParseError é PR 5 | `gzip_json_and_sse_request_stay_inspect` |
| gzip/deflate | `inspect` | Truncated / encoding no L0 | `gzip_json_and_sse_request_stay_inspect` |
| brotli | não suportado | `deny` se `require_complete`; senão `monitor` | `brotli_require_complete_default_deny_is_403`, `brotli_open_route_default_monitor_allows` |
| multipart | não suportado (sem parser por partes) | `deny` se `require_complete`; senão `monitor`. Nunca `inspect` | `multipart_require_complete_default_deny_is_403`, `multipart_is_never_inspect_complete` |
| versão HTTP desconhecida | não suportado | `deny` | `unknown_http_version_default_deny_is_403` |
| encoding desconhecido | não suportado | `deny` se `require_complete`; senão `monitor` | `unknown_encoding_*` |
| content-type desconhecido | não suportado | `deny` se `require_complete`; senão `monitor` | `unknown_content_type_*` |
| `route-to-quarantine` (qualquer linha) | — | 403 + evento `quarantine` (KD 20); sem sink | `route_to_quarantine_is_403_with_quarantine_event` |

`unsupported_rows_never_silent_inspect` trava o invariante: nenhuma linha da coluna “não suportado” devolve `Inspect`.

Quando várias linhas batem no mesmo request, vale a ação **mais severa**
(`route-to-quarantine` > `deny` > `monitor` > `bypass-explicit`).
`Upgrade: websocket` ou `Content-Encoding: br` não encobrem o `deny` de gRPC.
