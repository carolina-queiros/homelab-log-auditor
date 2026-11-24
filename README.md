# Homelab Log Auditor (Mini-SIEM & Active IPS)

Motor leve de deteção de intrusões e resposta ativa em tempo real para ambientes Linux, escrito em Python puro (zero dependências externas).

## Arquitetura

- **`engine/tailer.py`**: Leitor contínuo de logs (`tail -F`) com deteção automática de *log rotation* por alteração de *inode* ou truncagem.
- **`engine/detector.py`**: Motor de análise por expressões regulares e correlação temporal (*sliding window*) para identificar ataques SSH e HTTP.
- **`engine/storage.py`**: Persistência em SQLite (`auditor_state.db`) para histórico de alertas e gestão de bloqueios ativos com expiração (TTL).
- **`engine/responder.py`**: Módulo IPS que aplica bloqueios dinâmicos na firewall Linux via `nftables` (com *fallback* para `iptables`), suportando *whitelist* de redes seguras e modo `--dry-run`.
- **`engine/notifier.py`**: Envio de alertas estruturados via Webhook (Discord/Slack).

## Regras de Deteção Implementadas

| ID | Severidade | Vetor | Descrição |
| :--- | :--- | :--- | :--- |
| `SSH-BRUTE-001` | `HIGH` | SSH (`auth.log`) | Deteta *N* falhas de autenticação (`password` ou `publickey`, incluindo `invalid user`) numa janela temporal configurável. |
| `WEB-SQLI-002` | `CRITICAL` | HTTP Access Log | Identifica payloads de SQL Injection (`UNION SELECT`, `OR 1=1`, `SLEEP()`, etc.) nos pedidos. |
| `WEB-LFI-003` | `HIGH` | HTTP Access Log | Deteta tentativas de *Path Traversal* (`../`, `/etc/passwd`, `.env`). |
| `WEB-SCAN-004` | `MEDIUM` | HTTP Access Log | Deteta enumeração automatizada de caminhos sensíveis (`/wp-login.php`, `/phpmyadmin`, `/.git/config`). |

## Utilização

```bash
# Modo simulação (dry-run) seguro para validação sem alterações na firewall
python3 auditor.py --logs /var/log/auth.log /var/log/nginx/access.log --whitelist 192.168.1.0/24

# Modo ativo (IPS) com bloqueio real via nftables/iptables (requer root)
sudo python3 auditor.py --enforce --threshold 5 --window 60 --ban-ttl 3600

# Consultar relatório estatístico de incidentes e bloqueios ativos
python3 auditor.py --report

# Executar testes unitários
python3 -m unittest discover -s tests -v
