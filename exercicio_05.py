"""
Exercício 5 — O ORDER BY que o %s não protege (Aulas 3, 6, 7 e 8/A05)
GET /api/eventos?ordenar_por=&ordem=&tamanho=
Defesa com whitelist fechada — identificadores SQL nunca são parâmetros.
"""

import os
import mysql.connector
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Whitelists — a única porta de entrada para identificadores SQL
# ---------------------------------------------------------------------------

# Mapeamento de alias externo -> nome real de coluna
# Expor nomes internos do banco na API seria information disclosure.
COLUNAS: dict[str, str] = {
    "data": "criado_em",
    "sev":  "severidade",
    "ip":   "ip_origem",
}

# Alias externo -> valor SQL validado
ORDEM: dict[str, str] = {
    "asc":  "ASC",
    "desc": "DESC",
}

TAMANHO_PADRAO = 10
TAMANHO_MAXIMO = 100    # teto do servidor — proteção contra DoS de consulta


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
# Setup inicial (cria tabela e popula dados de exemplo)
# ---------------------------------------------------------------------------

DDL_EVENTOS = """
CREATE TABLE IF NOT EXISTS eventos (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    ip_origem   VARCHAR(15) NOT NULL,
    severidade  INT NOT NULL,
    criado_em   DATETIME DEFAULT CURRENT_TIMESTAMP
)
"""

EVENTOS_AMOSTRA = [
    ("10.0.0.1", 3),
    ("10.0.0.2", 5),
    ("10.0.0.3", 1),
    ("172.16.0.4", 4),
    ("192.168.1.5", 2),
    ("10.10.0.6", 5),
    ("10.0.0.7", 3),
]


def setup_db() -> None:
    with mysql_conn() as conn:
        cur = conn.cursor()
        cur.execute(DDL_EVENTOS)
        cur.execute("DELETE FROM eventos")
        cur.executemany(
            "INSERT INTO eventos (ip_origem, severidade) VALUES (%s, %s)",
            EVENTOS_AMOSTRA,
        )
        conn.commit()
    print("[MySQL] Tabela 'eventos' pronta com dados de amostra.")


# ---------------------------------------------------------------------------
# Rota principal
# ---------------------------------------------------------------------------

@app.route("/api/eventos")
def listar_eventos():
    """
    GET /api/eventos?ordenar_por=<alias>&ordem=<asc|desc>&tamanho=<n>

    Por que LIMIT %s funciona mas ORDER BY %s não:
    O protocolo de parametrização do MySQL substitui %s por um VALOR LITERAL
    (número, string entre aspas), jamais por um IDENTIFICADOR (nome de coluna).
    "ORDER BY 'criado_em'" é SQL válido mas ordena por uma constante,
    não pela coluna — resultado: dados sem ordem útil, ou erro silencioso.
    Concatenar o identificador sem validação abre ORDER BY injection:
    `?ordenar_por=(SELECT senha FROM usuarios LIMIT 1)` vira SQL real.
    Conclusão: dados são parâmetros; identificadores são código e precisam
    de whitelist — nunca chegam do usuário como estão.
    """

    # --- Validação de tamanho ---
    tamanho_raw = request.args.get("tamanho", str(TAMANHO_PADRAO))
    try:
        tamanho = int(tamanho_raw)
    except ValueError:
        return jsonify({"erro": "tamanho deve ser inteiro"}), 400

    # Aplica teto silencioso (não é erro — é proteção)
    tamanho = min(tamanho, TAMANHO_MAXIMO)
    tamanho = max(tamanho, 1)

    # --- Validação de coluna (whitelist) ---
    alias_coluna = request.args.get("ordenar_por", "data")
    coluna_sql   = COLUNAS.get(alias_coluna)
    if coluna_sql is None:
        return jsonify({"erro": "campo de ordenação inválido"}), 400

    # --- Validação de ordem (whitelist) ---
    alias_ordem = request.args.get("ordem", "asc")
    ordem_sql   = ORDEM.get(alias_ordem)
    if ordem_sql is None:
        return jsonify({"erro": "direção de ordenação inválida (use asc ou desc)"}), 400

    # --- Query: identificadores vindos EXCLUSIVAMENTE da whitelist ---
    # LIMIT usa %s (parâmetro de DADO) — isso é seguro.
    # ORDER BY usa a coluna da whitelist (identificador pré-aprovado) — não é injeção.
    query = f"SELECT id, ip_origem, severidade, criado_em FROM eventos ORDER BY {coluna_sql} {ordem_sql} LIMIT %s"

    try:
        with mysql_conn() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute(query, (tamanho,))
            rows = cur.fetchall()
    except mysql.connector.Error as e:
        app.logger.error("Erro de banco em /api/eventos: %s", e)
        return jsonify({"erro": "erro interno de banco"}), 500

    # Serializa datetime para string ISO
    for row in rows:
        if row.get("criado_em"):
            row["criado_em"] = row["criado_em"].isoformat()

    return jsonify(rows), 200


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    setup_db()
    print("=" * 72)
    print("EXERCÍCIO 5 — API de Eventos com Ordenação Segura")
    print("Servidor em http://localhost:5005")
    print("Testes:")
    print("  GET /api/eventos?ordenar_por=sev&ordem=desc&tamanho=5")
    print("  GET /api/eventos?ordenar_por=criado_em,(SELECT+1)&ordem=asc")
    print("  GET /api/eventos?tamanho=abc")
    print("  GET /api/eventos?tamanho=100000")
    print("=" * 72)
    app.run(debug=False, port=5005)
