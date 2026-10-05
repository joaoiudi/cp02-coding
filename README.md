# CP02 — Coding for Security

## Estrutura do projeto

```
exercicio_01.py          # Ex.1  — Assistente de decisão de armazenamento
exercicio_02.py          # Ex.2  — Migração MySQL → MongoDB
exercicio_03.py          # Ex.3  — Retenção TTL e janela temporal
exercicio_04.py          # Ex.4  — Transação com trilha de auditoria
exercicio_05.py          # Ex.5  — ORDER BY + whitelist (Flask)
exercicio_06.py          # Ex.6  — Controle de acesso + IDOR (Flask)
exercicio_07.py          # Ex.7  — XSS no atributo HTML (Flask + Jinja2)
exercicio_08.py          # Ex.8  — Modelo ML + API + auditoria (Flask)
exercicio_09.py          # Ex.9  — Rate limiting por anomalia (IsolationForest)
teste_ex09.py            # Script de teste para Ex.9
ex10_app_vulneravel.py   # Ex.10 — App vulnerável (laboratório)
ex10_app_seguro.py       # Ex.10 — App corrigido
ex10_exploit.py          # Ex.10 — Script de exploit/verificação
ex10_auditoria.md        # Ex.10 — Relatório de auditoria OWASP
.env                     # Variáveis de ambiente
```

## Pré-requisitos

```powershell
pip install pymongo mysql-connector-python scikit-learn numpy flask requests
```

## Configuração do ambiente

```powershell

# 1. Carregue as variáveis no PowerShell
Get-Content .env | ForEach-Object {
    if ($_ -match "^([^#=]+)=(.+)$") {
        [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim())
    }
}

# 2. Suba os bancos via Docker
docker run -d --name mongo-lab  -p 27017:27017 mongo:7
docker run -d --name mysql-lab  -p 3306:3306 -e MYSQL_ROOT_PASSWORD=$env:MYSQL_PASSWORD -e MYSQL_DATABASE=seguranca mysql:8
```

## Como executar cada exercício

```powershell
# Exercícios sem servidor (rodam e terminam)
python exercicio_01.py
python exercicio_02.py
python exercicio_03.py
python exercicio_04.py

# Exercícios com servidor Flask (rodam até Ctrl+C)
python exercicio_05.py   # porta 5005
python exercicio_06.py   # porta 5006
python exercicio_07.py   # porta 5007  -> abrir http://localhost:5007/dashboard
python exercicio_08.py   # porta 5008
python exercicio_09.py   # porta 5009  -> em outro terminal: python teste_ex09.py

# Exercício 10 — fluxo completo
python ex10_app_vulneravel.py   # porta 5010 (vulnerável)
# Em outro terminal:
python ex10_exploit.py          # demonstra os ataques

python ex10_app_seguro.py       # porta 5010 (seguro)
# Em outro terminal:
python ex10_exploit.py verificar  # verifica as defesas
```






