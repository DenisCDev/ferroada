# Snapshots de CIDR

Data deste snapshot: **2026-09-08**.

| Ficheiro | Fonte |
| --- | --- |
| `cloudflare.txt` | https://www.cloudflare.com/ips-v4 e https://www.cloudflare.com/ips-v6 |
| `fastly.txt` | https://api.fastly.com/public-ip-list |
| `akamai.txt` | https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.txt e `akamai_ipv6_CIDRs.txt` |

O processo Ferroada **não** descarrega estas listas. Cole-as em `TRUSTED_PROXIES` (vírgula) ou, no pack `cdn-edge`, use o valor já preenchido no `.env.example`.

Actualizar: `ferroada cidrs update` (opcionalmente `--edge cloudflare|fastly|akamai`, `--yes`, `--cidrs-from-network`). Mostra o diff, só escreve com confirmação ou `--yes`. Se o HTTP falhar, o ficheiro em disco não é tocado. O `init --trusted-proxies auto` continua a copiar só o snapshot local.
