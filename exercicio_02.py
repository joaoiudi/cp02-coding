"""
Exercício 2 — Migração relacional → documentos (Aulas 1, 2 e 3)
Lê com JOIN parametrizado do MySQL, insere documentos aninhados no MongoDB,
e verifica integridade comparando contagens.
"""

import os
import mysql.connector
from pymongo import MongoClient


# ---------------------------------------------------------------------------
# Conexões (credenciais via variável de ambiente — jamais no código)
# ---------------------------------------------------------------------------

def mysql_conn():
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", 3306)),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ["MYSQL_PASSWORD"],       # obrigatório via env
        database=os.environ.get("MYSQL_DB", "seguranca"),
    )


def mongo_client():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    return MongoClient(uri)


# ---------------------------------------------------------------------------
# 1. Cria e popula o MySQL
# ---------------------------------------------------------------------------

DDL_ATIVOS = """
CREATE TABLE IF NOT EXISTS ativos (
    id         INT PRIMARY KEY,
    nome       VARCHAR(50) NOT NULL,
    ip         VARCHAR(15) UNIQUE NOT NULL,
    criticidade ENUM('baixa','media','alta') NOT NULL
)
"""

DDL_ALERTAS = """
CREATE TABLE IF NOT EXISTS alertas (
    id        INT PRIMARY KEY,
    ativo_id  INT NOT NULL,
    tipo      VARCHAR(50) NOT NULL,
    severidade VARCHAR(20) NOT NULL,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ativo_id) REFERENCES ativos(id)
)
"""

ATIVOS_DADOS = [
    (1, "SRV-WEB01", "192.168.1.10", "alta"),
    (2, "PC-RH03",   "192.168.1.45", "baixa"),
]

ALERTAS_DADOS = [
    (1, 1, "BRUTE_FORCE", "critica"),
    (2, 1, "PORT_SCAN",   "alta"),
    (3, 2, "XSS",         "media"),
]


def criar_e_popular_mysql(conn):
    cur = conn.cursor()
    cur.execute(DDL_ATIVOS)
    cur.execute(DDL_ALERTAS)

    # Limpa para idempotência
    cur.execute("DELETE FROM alertas")
    cur.execute("DELETE FROM ativos")

    cur.executemany(
        "INSERT INTO ativos (id, nome, ip, criticidade) VALUES (%s, %s, %s, %s)",
        ATIVOS_DADOS,
    )
    cur.executemany(
        "INSERT INTO alertas (id, ativo_id, tipo, severidade) VALUES (%s, %s, %s, %s)",
        ALERTAS_DADOS,
    )
    conn.commit()
    print("[MySQL] Tabelas criadas e populadas.")


# ---------------------------------------------------------------------------
# 2. Lê com JOIN parametrizado e monta documentos
# ---------------------------------------------------------------------------

JOIN_QUERY = """
    SELECT
        al.id        AS alerta_id,
        al.tipo,
        al.severidade,
        al.criado_em,
        at.nome      AS ativo_nome,
        at.ip        AS ativo_ip,
        at.criticidade AS ativo_criticidade
    FROM alertas AS al
    JOIN ativos  AS at ON al.ativo_id = at.id
    ORDER BY al.id
"""
# Não há interpolação de strings — query completamente parametrizada.
# Os filtros futuros (ex.: WHERE at.criticidade = %s) usariam placeholder.


def buscar_alertas_com_join(conn) -> list[dict]:
    cur = conn.cursor(dictionary=True)
    cur.execute(JOIN_QUERY)          # sem parâmetros aqui; colunas são fixas
    return cur.fetchall()


def montar_documentos(linhas: list[dict]) -> list[dict]:
    """
    Transforma cada linha do JOIN em um documento MongoDB com subdocumento 'ativo'.
    O id_original é preservado para rastreabilidade durante a migração.
    """
    docs = []
    for linha in linhas:
        doc = {
            "_alerta_id_mysql": linha["alerta_id"],
            "tipo":       linha["tipo"],
            "severidade": linha["severidade"],
            "criado_em":  linha["criado_em"],
            "ativo": {
                "nome":        linha["ativo_nome"],
                "ip":          linha["ativo_ip"],
                "criticidade": linha["ativo_criticidade"],
            },
        }
        docs.append(doc)
    return docs


# ---------------------------------------------------------------------------
# 3. Insere no MongoDB e verifica integridade
# ---------------------------------------------------------------------------

def migrar(conn_mysql, client_mongo, db_name: str = "seguranca") -> None:
    db = client_mongo[db_name]
    colecao = db["alertas"]

    # Limpa para idempotência
    colecao.drop()

    linhas = buscar_alertas_com_join(conn_mysql)
    docs   = montar_documentos(linhas)
    colecao.insert_many(docs)

    # --- Verificação de integridade ---
    total_mysql = len(linhas)
    total_mongo = colecao.count_documents({})

    status = "MIGRAÇÃO ÍNTEGRA" if total_mysql == total_mongo else "DIVERGÊNCIA DETECTADA"
    print(f"\nMySQL: {total_mysql} alertas | MongoDB: {total_mongo} documentos -> {status}")

    # --- Consulta sem JOIN ---
    alta_criticidade = list(colecao.find(
        {"ativo.criticidade": "alta"},
        {"_id": 0, "tipo": 1, "ativo.nome": 1, "ativo.criticidade": 1},
    ))
    print(f"Consulta sem JOIN: db.alertas.find({{\"ativo.criticidade\":\"alta\"}}) -> {len(alta_criticidade)} documentos")
    for doc in alta_criticidade:
        print(f"  tipo={doc['tipo']} | ativo={doc['ativo']['nome']} | criticidade={doc['ativo']['criticidade']}")

    # --- Comentário obrigatório ---
    print("\n# O QUE SE GANHA: leituras de alertas com contexto do ativo não precisam")
    print("#   de JOIN — o documento é auto-contido, reduzindo latência e complexidade")
    print("#   de consulta. Ideal para dashboards de SOC que leem muito e escrevem pouco.")
    print("# O QUE SE PERDE: dados do ativo ficam duplicados em cada alerta;")
    print("#   renomear ou mudar o IP de 'SRV-WEB01' exige db.alertas.update_many(")
    print("#   {\"ativo.nome\":\"SRV-WEB01\"}, {\"$set\":{\"ativo.ip\":\"novo_ip\"}}),")
    print("#   o que não é atômico e pode deixar documentos inconsistentes se falhar.")


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 2 — Migração Relacional → Documentos")
    print("=" * 72)

    with mysql_conn() as conn_mysql:
        criar_e_popular_mysql(conn_mysql)
        with mongo_client() as client_mongo:
            migrar(conn_mysql, client_mongo)
