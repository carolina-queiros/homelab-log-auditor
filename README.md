# Homelab Log Auditor (Mini-SIEM & Active IPS)

Sistema leve de deteção de intrusões (SIEM), resposta ativa na firewall (IPS) e observabilidade em tempo real para ambientes Linux, escrito em Python puro (biblioteca padrão, zero dependências externas).

## Arquitetura Modular

- **`engine/config.py` & `config.json`**: Gestão de configuração externa com validação de expressões regulares e suporte para recarga dinâmica sem paragem via sinal `SIGHUP`.
- **`engine/tailer.py`**: Leitor contínuo de logs (`tail -F`) com deteção automática de *log rotation* por alteração de *inode* ou truncagem.
- **`engine/detector.py`**: Motor de análise por regras Regex (nativas + customizadas) e correlação temporal (*sliding window*).
- **`engine/storage.py`**: Persistência em SQLite para alertas, bloqueios ativos com TTL e **ban progressivo (*escalation*)** para IPs reincidentes (`1x` $\rightarrow$ `4x` $\rightarrow$ `16x`, até ao teto de 7 dias).
- **`engine/responder.py`**: Módulo IPS que aplica bloqueios dinâmicos na firewall Linux via `nftables` (com *fallback* para `iptables`), *whitelist* CIDR e modo `--dry-run`.
- **`engine/dashboard.py`**: Servidor HTTP multi-thread com API REST (`/api/stats`, `/api/alerts`, `/api/bans`, `/api/unban`) e dashboard web em tempo real protegido contra XSS.
- **`engine/notifier.py`**: Alertas estruturados via Webhook (Discord/Slack).
- **`deploy/` & `Dockerfile`**: Unit `systemd` endurecida (`ProtectSystem=strict`, `CAP_NET_ADMIN`) e imagem Docker sem privilégios (`USER auditor`).

## Regras de Deteção Nativas

| ID | Severidade | Vetor | Descrição |
| :--- | :--- | :--- | :--- |
| `SSH-BRUTE-001` | `HIGH` | SSH (`auth.log`) | Deteta *N* falhas de autenticação (`password` ou `publickey`, incluindo `invalid user`) numa janela temporal configurável. |
| `WEB-SQLI-002` | `CRITICAL` | HTTP Access Log | Identifica payloads de SQL Injection (`UNION SELECT`, `OR 1=1`, `SLEEP()`, etc.) nos pedidos. |
| `WEB-LFI-003` | `HIGH` | HTTP Access Log | Deteta tentativas de *Path Traversal* (`../`, `/etc/passwd`, `.env`). |
| `WEB-SCAN-004` | `MEDIUM` | HTTP Access Log | Deteta enumeração automatizada de caminhos sensíveis (`/wp-login.php`, `/phpmyadmin`, `/.git/config`). |

## Utilização

```bash
# Modo simulação (dry-run) com dashboard web ativo em [http://127.0.0.1:8080](http://127.0.0.1:8080)
python3 auditor.py --config config.json --web

# Modo ativo (IPS) com bloqueio real via nftables/iptables
sudo python3 auditor.py --config config.json --enforce --web

# Recarregar regras do config.json em tempo real sem reiniciar o daemon
kill -HUP $(pgrep -f auditor.py)

# Consultar relatório estatístico na consola
python3 auditor.py --report

# Executar suíte completa de testes unitários
python3 -m unittest discover -s tests -v
