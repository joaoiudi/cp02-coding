# Exercício 10 — Auditoria de Segurança: Antes e Depois

> **Ambiente:** `app_vulneravel.py` vs `app_seguro.py`  
> **Referência:** OWASP Top 10 (2025)  
> **Lei:** Uso exclusivo contra cópia local — Lei 12.737/2012 proíbe acesso não autorizado.

---

## Falhas encontradas (≥ 8 obrigatórias)

| # | Código OWASP 2025 | Localização no código | Impacto | Correção aplicada |
|---|---|---|---|---|
| 1 | **A03 — Injeção** | `buscar()`: `f"SELECT * ... '%{nome}%'"` | Atacante extrai toda a tabela com `' OR '1'='1`; pode apagar ou alterar dados com comandos encadeados (stacked queries, dependendo do driver). | `cursor.execute("... LIKE %s", (f"%{nome}%",))` — placeholder parametrizado; o driver escapa o valor como dado, não como SQL. |
| 2 | **A03 — Injeção (XSS)** | `perfil()`: `f"<h1>Bem-vindo, {u}</h1>"` | Entrada do usuário renderizada como HTML raw: `?u=<script>alert(1)</script>` executa no navegador da vítima (session hijacking, phishing, defacement). | Rota retorna JSON; o cliente renderiza com escape. Alternativa: Jinja2 sem `\|safe`. |
| 3 | **A01 — Controle de Acesso Quebrado** | `remover()`: sem autenticação nem autorização | Qualquer pessoa na rede pode apagar qualquer usuário com `DELETE /api/usuarios/<id>` sem fornecer credencial. | Decorador `@autenticar(nivel_minimo=5)` exige `X-API-Key` válida de nível ≥ 5. |
| 4 | **A05 — Misconfiguration (vazamento de erro)** | `relatorio()`: exceção não tratada | Flask no modo debug retorna traceback completo com nome de tabela, stack trace e versão do banco — informação de ouro para reconhecimento. | `try/except mysql.connector.Error`: log interno; resposta genérica `{"erro":"erro interno"}`. |
| 5 | **A02 — Falhas Criptográficas (dados sensíveis)** | `buscar()`: `SELECT *` retorna coluna `senha` | Hash de senha (ou senha em texto claro) é exposto na API pública — violação direta do princípio de minimização. | `SELECT id, nome, email, nivel` — coluna `senha` **nunca** entra no payload de resposta. |
| 6 | **A05 — Misconfiguration (headers)** | *AUSÊNCIA* — nenhum header de segurança em nenhuma resposta | Sem `Content-Security-Policy`, XSS fica sem segunda camada de defesa. Sem `X-Frame-Options`, site é embutível em iframe (clickjacking). Sem `X-Content-Type-Options`, MIME sniffing pode executar scripts disfarçados. | `@app.after_request` injeta `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` em **todas** as respostas. |
| 7 | **A09 — Falhas de Registro e Monitoramento** | *AUSÊNCIA* — zero logging de requisições ou eventos de segurança | Ataques ocorrem sem rastro: nenhum alerta, nenhuma evidência forense. "Ataque que não deixa rastro é ataque invisível." | `@app.before_request` / `@app.after_request` registram método, rota, IP, User-Agent, status code e duração em cada requisição. |
| 8 | **A02 — Falhas Criptográficas (credenciais hardcoded)** | `SENHA_MESTRA = "Cyber@2024"` e `password="senha"` | Senha exposta no código-fonte: qualquer desenvolvedor com acesso ao repositório, qualquer vazamento de código ou snapshot de container tem acesso ao banco de produção imediatamente. | Credenciais lidas de `os.environ["MYSQL_PASSWORD"]` — `KeyError` deliberado se a variável não estiver definida, impedindo subida do serviço sem configuração. |
| 9 | **A05 — Misconfiguration (modo debug)** | `app.run(debug=True, host="0.0.0.0")` | `debug=True` habilita o console interativo do Werkzeug: qualquer usuário que provoque uma exceção recebe um shell Python no servidor. `host="0.0.0.0"` expõe esse console para toda a rede. | `debug=False`, `host="127.0.0.1"` — escuta apenas localmente; em produção, usar proxy reverso (nginx/gunicorn). |

---

## Resultado esperado do exploit.py

### Antes (contra `app_vulneravel.py`)

```
[1] SQL Injection em buscar  -> 3 usuários retornados, senhas expostas  VAZAMENTO
[2] XSS em /perfil           -> payload volta cru no HTML               XSS
[3] DELETE sem credencial    -> 200, usuário apagado                    ACESSO INDEVIDO
[4] GET /api/relatorio       -> 500 com traceback e nome da tabela      VAZAMENTO
[5] GET /api/usuarios/buscar -> coluna senha presente na resposta       DADOS SENSÍVEIS
[6] Headers de segurança     -> CSP, X-Frame, X-Content ausentes        MISCONFIGURATION
=== 6 de 6 ataques bem-sucedidos ===
```

### Depois (contra `app_seguro.py`)

```
[1] -> 0 usuários (parametrizado)               DEFENDIDO
[2] -> payload escapado / JSON sem HTML          DEFENDIDO
[3] -> 401 sem credencial / 403 sem nível        DEFENDIDO
[4] -> 500 {"erro":"erro interno"} sem detalhe   DEFENDIDO
[5] -> resposta sem coluna senha                 DEFENDIDO
[6] -> 3 headers presentes                       DEFENDIDO
=== 0 de 6 ataques bem-sucedidos ===
```

---

## Como executar

```bash
# 1. Suba os bancos (Docker)
docker compose up -d mongo-lab mysql-lab

# 2. Configure credenciais
$env:MYSQL_PASSWORD = "sua_senha"
$env:MONGO_URI      = "mongodb://localhost:27017/"

# 3. App vulnerável (porta 5010)
python ex10_app_vulneravel.py   # edite a porta para 5010 se necessário

# 4. Execute o exploit (contra vulnerável)
python ex10_exploit.py

# 5. App seguro (porta 5010)
python ex10_app_seguro.py

# 6. Execute a verificação (contra seguro)
python ex10_exploit.py verificar
```
