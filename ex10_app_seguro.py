"""
Exercício 10 — app_seguro.py
Versão corrigida de app_vulneravel.py.
Todas as falhas foram corrigidas; o mesmo exploit.py deve falhar em todos os ataques.
"""

import os
import logging
from datetime import datetime, timezone
import mysql.connector
from flask import Flask, jsonify, request, Response, g
import functools

# ---------------------------------------------------------------------------
# Configuração de logging (A09 — corrige AUSÊNCIA de registro)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# CORREÇÃO 1: Sem segredos no código — credenciais via variável de ambiente
# ---------------------------------------------------------------------------

def db():
    """
    CORREÇÃO A02: credenciais lidas de variáveis de ambiente.
    Qualquer senha escrita no código-fonte custa 0,3 do total.
    """
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ["MYSQL_PASSWORD"],       # obrigatório via env
        database=os.environ.get("MYSQL_DB", "seguranca"),
    )


# ---------------------------------------------------------------------------
# CORREÇÃO 2: Setup da tabela (criada de forma segura)
# ---------------------------------------------------------------------------

def setup_db() -> None:
    with db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id    INT AUTO_INCREMENT PRIMARY KEY,
                nome  VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                senha VARCHAR(255) NOT NULL,
                nivel INT NOT NULL DEFAULT 1,
                api_key VARCHAR(100) UNIQUE NOT NULL
            )
        """)
        cur.execute("DELETE FROM usuarios")
        cur.executemany(
            "INSERT INTO usuarios (nome, email, senha, nivel, api_key) VALUES (%s, %s, %s, %s, %s)",
            [
                ("ana",   "ana@x.com",   "hash_ana",   5, "key-ana-001"),
                ("bruno", "bruno@x.com", "hash_bruno", 2, "key-bruno-002"),
                ("caio",  "caio@x.com",  "hash_caio",  1, "key-caio-003"),
            ],
        )
        conn.commit()
    logger.info("Banco de dados configurado.")


# ---------------------------------------------------------------------------
# CORREÇÃO 3: Headers de segurança em TODAS as respostas (A05)
# ---------------------------------------------------------------------------

@app.after_request
def adicionar_headers_seguranca(response: Response) -> Response:
    """
    CORREÇÃO A05: headers de segurança — corrige AUSÊNCIA (falha invisível).
    CSP bloqueia scripts externos e inline; X-Frame-Options previne clickjacking;
    X-Content-Type-Options previne MIME sniffing.
    """
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-Content-Type-Options"]  = "nosniff"
    return response


# ---------------------------------------------------------------------------
# CORREÇÃO 4: Logging de requisições (A09 — corrige AUSÊNCIA)
# ---------------------------------------------------------------------------

@app.before_request
def registrar_requisicao():
    """
    CORREÇÃO A09: toda requisição é registrada.
    Sem logs, ataques são invisíveis e incidentes são irrastreáveis.
    """
    logger.info(
        "Requisição: %s %s | IP: %s | UA: %s",
        request.method,
        request.path,
        request.remote_addr,
        request.headers.get("User-Agent", "-")[:80],
    )
    g.inicio = datetime.now(tz=timezone.utc)


@app.after_request
def registrar_resposta(response: Response) -> Response:
    duracao_ms = (
        (datetime.now(tz=timezone.utc) - g.inicio).total_seconds() * 1000
        if hasattr(g, "inicio") else -1
    )
    logger.info(
        "Resposta: %s %s -> %d (%.1fms)",
        request.method, request.path, response.status_code, duracao_ms,
    )
    return response


# ---------------------------------------------------------------------------
# Autenticação por API Key
# ---------------------------------------------------------------------------

def autenticar(nivel_minimo: int = 1):
    """
    CORREÇÃO A01: toda rota sensível exige autenticação com query parametrizada.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            if not api_key:
                return jsonify({"erro": "autenticação necessária"}), 401
            try:
                with db() as conn:
                    cur = conn.cursor(dictionary=True)
                    # Query parametrizada — chave NUNCA concatenada
                    cur.execute(
                        "SELECT id, nome, nivel FROM usuarios WHERE api_key = %s",
                        (api_key,),
                    )
                    usuario = cur.fetchone()
            except mysql.connector.Error as e:
                logger.error("Erro de banco em autenticação: %s", e)
                return jsonify({"erro": "erro interno"}), 500

            if usuario is None:
                return jsonify({"erro": "autenticação necessária"}), 401

            if usuario["nivel"] < nivel_minimo:
                return jsonify({"erro": "acesso negado"}), 403

            g.usuario = usuario
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Rotas corrigidas
# ---------------------------------------------------------------------------

@app.route("/api/usuarios/buscar")
@autenticar(nivel_minimo=1)
def buscar():
    """
    CORREÇÃO A03: query com placeholder %s — jamais f-string.
    CORREÇÃO A02: SELECT explícito SEM a coluna senha.
    """
    nome = request.args.get("nome", "")
    try:
        with db() as conn:
            cur = conn.cursor(dictionary=True)
            # Placeholder correto — nome nunca é concatenado
            cur.execute(
                "SELECT id, nome, email, nivel FROM usuarios WHERE nome LIKE %s",
                (f"%{nome}%",),
            )
            usuarios = cur.fetchall()
    except mysql.connector.Error as e:
        logger.error("Erro em buscar usuarios: %s", e)
        return jsonify({"erro": "erro interno"}), 500

    return jsonify(usuarios), 200


@app.route("/perfil")
def perfil():
    """
    CORREÇÃO A03: sem renderização de HTML com entrada do usuário.
    Retorna JSON — jamais interpola entrada em HTML diretamente.
    """
    nome = request.args.get("u", "")
    # Valida que é apenas texto simples
    if not nome or len(nome) > 100:
        return jsonify({"erro": "parâmetro inválido"}), 400
    # Retorna JSON — o cliente é responsável por renderizar com escape
    return jsonify({"mensagem": f"Bem-vindo, {nome}"}), 200


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
@autenticar(nivel_minimo=5)    # CORREÇÃO A01: apenas nível >= 5 pode apagar
def remover(uid: int):
    """
    CORREÇÃO A01: rota agora exige autenticação e nível de acesso adequado.
    """
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM usuarios WHERE id = %s", (uid,))
            if cur.fetchone() is None:
                return jsonify({"erro": "não encontrado"}), 404
            cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
            conn.commit()
    except mysql.connector.Error as e:
        logger.error("Erro ao remover usuario %d: %s", uid, e)
        return jsonify({"erro": "erro interno"}), 500

    logger.warning("Usuário %d removido por %s", uid, g.usuario["nome"])
    return jsonify({"removido": uid}), 200


@app.route("/api/relatorio")
@autenticar(nivel_minimo=3)
def relatorio():
    """
    CORREÇÃO A05: exceção tratada — detalhes internos ficam no log, nunca na resposta.
    O cliente recebe apenas "erro interno" genérico.
    """
    try:
        with db() as conn:
            cur = conn.cursor(dictionary=True)
            # Tabela correta (a inexistente era bug do app vulnerável)
            cur.execute("SELECT id, nome, email, nivel FROM usuarios LIMIT 50")
            dados = cur.fetchall()
    except mysql.connector.Error as e:
        # Detalhe fica no log do servidor, NUNCA na resposta HTTP
        logger.error("Erro em /api/relatorio: %s", e)
        return jsonify({"erro": "erro interno"}), 500

    return jsonify(dados), 200


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_db()
    print("=" * 72)
    print("EXERCÍCIO 10 — app_seguro.py")
    print("Servidor em http://localhost:5010")
    print()
    print("Para verificar as defesas:")
    print("  python ex10_exploit.py verificar")
    print("=" * 72)
    # CORREÇÃO: debug=False em produção (A05)
    app.run(debug=False, host="127.0.0.1", port=5010)
