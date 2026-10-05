"""
Exercício 7 — XSS onde ninguém procura: dentro do atributo (Aulas 6, 7 e 8/A05)
GET /dashboard — tabela de incidentes do MongoDB com CSP header.
/dashboard-inseguro — versão vulnerável para comparação.
"""

import os
from pymongo import MongoClient
from flask import Flask, render_template_string, Response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CSP header em todas as respostas (A05 / Misconfiguration)
# ---------------------------------------------------------------------------

@app.after_request
def aplicar_headers_seguranca(response: Response) -> Response:
    """
    Content-Security-Policy bloqueia scripts inline e recursos externos.
    Mesmo que o Jinja2 escapasse o XSS, um |safe acidental reabriria o buraco.
    A CSP é a segunda camada — defesa em profundidade.
    """
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    return response


# ---------------------------------------------------------------------------
# Dados de demonstração
# ---------------------------------------------------------------------------

PAYLOADS = [
    {
        "titulo":  "<script>alert('xss1')</script>",
        "ativo":   "SRV-WEB01",
        "severidade": "critica",
    },
    {
        "titulo":  'x" onerror="alert(\'xss2\')',
        "ativo":   'x" onerror="alert(\'xss3\')',   # payload no nome do ativo também
        "severidade": "alta",
    },
]


def mongo_client():
    return MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))


def setup_mongo() -> None:
    with mongo_client() as client:
        db  = client[os.environ.get("MONGO_DB", "seguranca")]
        col = db["incidentes_xss_demo"]
        col.drop()
        col.insert_many(PAYLOADS)
    print("[MongoDB] Coleção 'incidentes_xss_demo' populada com payloads XSS.")


def buscar_incidentes() -> list[dict]:
    with mongo_client() as client:
        db  = client[os.environ.get("MONGO_DB", "seguranca")]
        col = db["incidentes_xss_demo"]
        return list(col.find({}, {"_id": 0}))


# ---------------------------------------------------------------------------
# Template SEGURO — Jinja2 escapa por padrão
# ---------------------------------------------------------------------------

# Por que |safe reabriria o buraco:
# Jinja2 trata cada variável como dado não confiável e escapa caracteres especiais
# HTML (< > " ' &) antes de renderizar. Se um desenvolvedor adicionar |safe
# (ex.: {{ incidente.titulo|safe }}) ele diz ao Jinja2 "confie nessa string,
# não escape" — mas a string veio do banco, que pode ter sido alimentado por
# um atacante. Com |safe, o payload <script>alert(1)</script> é renderizado
# como tag HTML real, executando o script no navegador da vítima.

TEMPLATE_SEGURO = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Dashboard de Incidentes (Seguro)</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
    th { background: #f0f0f0; }
    .aviso { color: #007700; font-weight: bold; }
  </style>
</head>
<body>
  <h1>Dashboard de Incidentes</h1>
  <p class="aviso">✅ Versão segura — Jinja2 escapa todos os valores por padrão.</p>
  <table>
    <thead>
      <tr><th>Título</th><th>Ativo</th><th>Severidade</th></tr>
    </thead>
    <tbody>
      {% for inc in incidentes %}
      <tr>
        {# {{ inc.titulo }} é escapado — <script> vira &lt;script&gt; #}
        <td>{{ inc.titulo }}</td>
        {# alt também é escapado — " vira &quot; impedindo saída do atributo #}
        <td><img src="/icone.png" alt="{{ inc.ativo }}" style="display:none">{{ inc.ativo }}</td>
        <td>{{ inc.severidade }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <br>
  <a href="/dashboard-inseguro">⚠️ Ver versão insegura (comparação)</a>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Template INSEGURO — usa |safe para mostrar o contraste
# ---------------------------------------------------------------------------

TEMPLATE_INSEGURO = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Dashboard INSEGURO (demonstração)</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; background: #fff0f0; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; }
    th { background: #fcc; }
    .aviso { color: #cc0000; font-weight: bold; font-size: 1.1rem; }
  </style>
</head>
<body>
  <h1>⚠️ Dashboard INSEGURO — apenas para demonstração local</h1>
  <p class="aviso">❌ |safe desabilitado o escape do Jinja2 — payloads executam!</p>
  <table>
    <thead>
      <tr><th>Título</th><th>Ativo</th><th>Severidade</th></tr>
    </thead>
    <tbody>
      {% for inc in incidentes %}
      <tr>
        {# |safe diz "confie nessa string" — MAS ela veio do banco/usuário #}
        <td>{{ inc.titulo | safe }}</td>
        {# payload no alt sai do atributo porque " não foi escapado #}
        <td><img src="/icone.png" alt="{{ inc.ativo | safe }}">{{ inc.ativo | safe }}</td>
        <td>{{ inc.severidade }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <br>
  <a href="/dashboard">✅ Ver versão segura</a>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------

@app.route("/dashboard")
def dashboard_seguro():
    incidentes = buscar_incidentes()
    html = render_template_string(TEMPLATE_SEGURO, incidentes=incidentes)
    return Response(html, mimetype="text/html")


@app.route("/dashboard-inseguro")
def dashboard_inseguro():
    """
    Rota claramente marcada para comparação lado a lado.
    Demonstra o que acontece com |safe mal colocado.
    ⚠️  Apenas para uso local — nunca expor em produção.
    """
    incidentes = buscar_incidentes()
    html = render_template_string(TEMPLATE_INSEGURO, incidentes=incidentes)
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_mongo()
    print("=" * 72)
    print("EXERCÍCIO 7 — XSS no atributo HTML")
    print("Servidor em http://localhost:5007")
    print("  /dashboard         -> versão segura (Jinja2 + CSP)")
    print("  /dashboard-inseguro -> versão |safe para comparação")
    print("=" * 72)
    app.run(debug=False, port=5007)
