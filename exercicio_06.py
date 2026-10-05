"""
Exercício 6 — Controle de acesso quebrado (Aulas 3, 6 e 8/A01)
API de incidentes: analista vê apenas os seus; nivel >= 5 pode apagar qualquer um.
Autenticação por X-API-Key validada com query parametrizada.
"""

import os
import functools

import mysql.connector
from flask import Flask, jsonify, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Conexão MySQL
# ---------------------------------------------------------------------------

def mysql_conn():
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", 3306)),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ["MYSQL_PASSWORD"],
        database=os.environ.get("MYSQL_DB", "seguranca"),
    )


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

DDL_ANALISTAS = """
CREATE TABLE IF NOT EXISTS analistas (
    id       INT PRIMARY KEY,
    nome     VARCHAR(50) NOT NULL,
    api_key  VARCHAR(100) UNIQUE NOT NULL,
    nivel    INT NOT NULL
)
"""

DDL_INCIDENTES = """
CREATE TABLE IF NOT EXISTS incidentes (
    id         INT PRIMARY KEY,
    dono_id    INT NOT NULL,
    titulo     VARCHAR(100) NOT NULL,
    severidade VARCHAR(20) NOT NULL,
    status     VARCHAR(20) DEFAULT 'aberto',
    FOREIGN KEY (dono_id) REFERENCES analistas(id)
)
"""

ANALISTAS_DADOS = [
    (1, "ana",   "key-ana-001",   5),
    (2, "bruno", "key-bruno-002", 2),
]

INCIDENTES_DADOS = [
    (1, 1, "Brute force SSH", "critica", "aberto"),
    (2, 2, "Phishing no RH",  "media",   "aberto"),
]


def setup_db() -> None:
    with mysql_conn() as conn:
        cur = conn.cursor()
        cur.execute(DDL_ANALISTAS)
        cur.execute(DDL_INCIDENTES)
        cur.execute("DELETE FROM incidentes")
        cur.execute("DELETE FROM analistas")
        cur.executemany(
            "INSERT INTO analistas (id, nome, api_key, nivel) VALUES (%s, %s, %s, %s)",
            ANALISTAS_DADOS,
        )
        cur.executemany(
            "INSERT INTO incidentes (id, dono_id, titulo, severidade, status) VALUES (%s, %s, %s, %s, %s)",
            INCIDENTES_DADOS,
        )
        conn.commit()
    print("[MySQL] Tabelas 'analistas' e 'incidentes' prontas.")


# ---------------------------------------------------------------------------
# Autenticação — decorador reutilizável
# ---------------------------------------------------------------------------

def autenticar(f):
    """
    Valida X-API-Key contra o banco com query parametrizada.
    Injeta o analista autenticado em kwargs["analista_autenticado"].
    Distinção semântica:
      401 — "não sei quem você é" (header ausente ou chave inválida)
      403 — "sei quem você é e você não pode" (recurso de outro analista)
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"erro": "autenticação necessária"}), 401

        try:
            with mysql_conn() as conn:
                cur = conn.cursor(dictionary=True)
                # Query parametrizada — chave nunca é concatenada
                cur.execute(
                    "SELECT id, nome, nivel FROM analistas WHERE api_key = %s",
                    (api_key,),
                )
                analista = cur.fetchone()
        except mysql.connector.Error as e:
            app.logger.error("Erro de banco em autenticação: %s", e)
            return jsonify({"erro": "erro interno"}), 500

        if analista is None:
            # Chave não existe — mesmo status que "sem header" (não revela diferença)
            return jsonify({"erro": "autenticação necessária"}), 401

        kwargs["analista_autenticado"] = analista
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------

@app.route("/api/incidentes")
@autenticar
def listar_incidentes(analista_autenticado):
    """
    Retorna apenas os incidentes do analista autenticado.
    A cláusula WHERE dono_id = %s garante isolamento — sem filtragem em Python.
    """
    try:
        with mysql_conn() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, titulo, severidade, status FROM incidentes WHERE dono_id = %s",
                (analista_autenticado["id"],),
            )
            incidentes = cur.fetchall()
    except mysql.connector.Error as e:
        app.logger.error("Erro ao listar incidentes: %s", e)
        return jsonify({"erro": "erro interno"}), 500

    return jsonify(incidentes), 200


@app.route("/api/incidentes/<int:iid>")
@autenticar
def obter_incidente(iid: int, analista_autenticado):
    """
    Retorna um incidente específico.
    403 para IDOR (acesso a incidente de outro analista) — o corpo NÃO
    revela se o incidente existe, impedindo enumeração de recursos.
    """
    try:
        with mysql_conn() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT id, dono_id, titulo, severidade, status FROM incidentes WHERE id = %s",
                (iid,),
            )
            incidente = cur.fetchone()
    except mysql.connector.Error as e:
        app.logger.error("Erro ao obter incidente %d: %s", iid, e)
        return jsonify({"erro": "erro interno"}), 500

    if incidente is None:
        return jsonify({"erro": "não encontrado"}), 404

    # Verifica ownership — resposta genérica para não revelar existência
    if incidente["dono_id"] != analista_autenticado["id"]:
        # 403: sabemos quem é o analista, mas ele não tem acesso
        # A mensagem NÃO diz "esse incidente existe mas não é seu"
        return jsonify({"erro": "acesso negado"}), 403

    incidente.pop("dono_id")   # não expõe ID interno de dono
    return jsonify(incidente), 200


@app.route("/api/incidentes/<int:iid>", methods=["DELETE"])
@autenticar
def remover_incidente(iid: int, analista_autenticado):
    """
    Apenas analistas com nivel >= 5 podem apagar qualquer incidente.
    """
    if analista_autenticado["nivel"] < 5:
        return jsonify({"erro": "acesso negado"}), 403

    try:
        with mysql_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM incidentes WHERE id = %s",
                (iid,),
            )
            if cur.fetchone() is None:
                return jsonify({"erro": "não encontrado"}), 404

            cur.execute("DELETE FROM incidentes WHERE id = %s", (iid,))
            conn.commit()
    except mysql.connector.Error as e:
        app.logger.error("Erro ao remover incidente %d: %s", iid, e)
        return jsonify({"erro": "erro interno"}), 500

    return jsonify({"removido": iid}), 200


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_db()
    print("=" * 72)
    print("EXERCÍCIO 6 — Controle de Acesso Quebrado (A01)")
    print("Servidor em http://localhost:5006")
    print("Matriz de testes (curl):")
    print('  curl -H "X-API-Key: key-ana-001"   http://localhost:5006/api/incidentes/1')
    print('  curl -H "X-API-Key: key-bruno-002" http://localhost:5006/api/incidentes/1')
    print('  curl                               http://localhost:5006/api/incidentes/1')
    print('  curl -H "X-API-Key: key-inexistente" http://localhost:5006/api/incidentes/1')
    print('  curl -H "X-API-Key: key-bruno-002" http://localhost:5006/api/incidentes')
    print('  curl -X DELETE -H "X-API-Key: key-ana-001" http://localhost:5006/api/incidentes/2')
    print('  curl -X DELETE -H "X-API-Key: key-bruno-002" http://localhost:5006/api/incidentes/1')
    print('  curl -H "X-API-Key: key-ana-001" http://localhost:5006/api/incidentes/999')
    print("=" * 72)
    app.run(debug=False, port=5006)
