"""
Exercício 4 — Transação com trilha de auditoria (Aulas 2, 3 e 8/A09)
alterar_nivel(admin_id, alvo_id, novo_nivel):
  - Transação MySQL com commit/rollback
  - Validações de negócio (privilégio, auto-promoção, existência)
  - TODA tentativa grava documento de auditoria no MongoDB (A09)
"""

import os
from datetime import datetime, timezone
from enum import Enum

import mysql.connector
from pymongo import MongoClient


# ---------------------------------------------------------------------------
# Enums de resultado — torna o código autodocumentado
# ---------------------------------------------------------------------------

class Resultado(str, Enum):
    SUCESSO          = "SUCESSO"
    RECUSADO         = "RECUSADO"


class MotivoRecusa(str, Enum):
    SEM_PRIVILEGIO  = "admin sem privilégio (nivel_acesso < 5)"
    AUTO_PROMOCAO   = "auto-promoção não permitida"
    ALVO_INEXISTENTE = "alvo não encontrado"


# ---------------------------------------------------------------------------
# Conexões
# ---------------------------------------------------------------------------

def mysql_conn():
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", 3306)),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ["MYSQL_PASSWORD"],
        database=os.environ.get("MYSQL_DB", "seguranca"),
        autocommit=False,   # transação manual
    )


def mongo_client():
    return MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))


# ---------------------------------------------------------------------------
# Setup MySQL
# ---------------------------------------------------------------------------

DDL_USUARIOS = """
CREATE TABLE IF NOT EXISTS usuarios (
    id            INT PRIMARY KEY,
    nome          VARCHAR(50) NOT NULL,
    email         VARCHAR(100) UNIQUE NOT NULL,
    nivel_acesso  INT NOT NULL
)
"""

USUARIOS = [
    (1, "ana",   "ana@x.com",   5),
    (2, "bruno", "bruno@x.com", 2),
    (3, "caio",  "caio@x.com",  1),
]


def setup_mysql(conn) -> None:
    cur = conn.cursor()
    cur.execute(DDL_USUARIOS)
    cur.execute("DELETE FROM usuarios")
    cur.executemany(
        "INSERT INTO usuarios (id, nome, email, nivel_acesso) VALUES (%s, %s, %s, %s)",
        USUARIOS,
    )
    conn.commit()
    print("[MySQL] Tabela 'usuarios' criada e populada.")


# ---------------------------------------------------------------------------
# Função principal
# ---------------------------------------------------------------------------

def alterar_nivel(
    admin_id: int,
    alvo_id:  int,
    novo_nivel: int,
    conn_mysql,
    col_auditoria,
) -> dict:
    """
    Altera o nível de acesso de um usuário dentro de uma transação MySQL.
    Registra a tentativa no MongoDB independentemente do resultado (A09).

    Retorna um dict com resultado, motivo (se recusado) e dados da operação.
    """
    cur = conn_mysql.cursor(dictionary=True)

    # --- Busca o admin (query parametrizada) ---
    cur.execute(
        "SELECT id, nome, nivel_acesso FROM usuarios WHERE id = %s",
        (admin_id,),
    )
    admin = cur.fetchone()

    # --- Busca o alvo (query parametrizada) ---
    cur.execute(
        "SELECT id, nome, nivel_acesso FROM usuarios WHERE id = %s",
        (alvo_id,),
    )
    alvo = cur.fetchone()

    nivel_anterior = alvo["nivel_acesso"] if alvo else None

    # --- Validações de negócio ---
    recusa = None

    if admin is None or admin["nivel_acesso"] < 5:
        recusa = MotivoRecusa.SEM_PRIVILEGIO
    elif admin_id == alvo_id:
        recusa = MotivoRecusa.AUTO_PROMOCAO
    elif alvo is None:
        recusa = MotivoRecusa.ALVO_INEXISTENTE

    if recusa:
        conn_mysql.rollback()
        resultado = Resultado.RECUSADO
        _registrar_auditoria(
            col_auditoria,
            quem=admin_id,
            alvo=alvo_id,
            nivel_anterior=nivel_anterior,
            nivel_novo=novo_nivel,
            resultado=resultado,
            motivo=recusa.value,
        )
        msg = f"RECUSADO ({recusa.value}). rollback."
        if alvo:
            msg += f" {alvo['nome']}: {nivel_anterior}"
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> {msg}")
        return {"resultado": resultado, "motivo": recusa.value}

    # --- Alteração dentro da transação ---
    cur.execute(
        "UPDATE usuarios SET nivel_acesso = %s WHERE id = %s",
        (novo_nivel, alvo_id),
    )
    conn_mysql.commit()

    resultado = Resultado.SUCESSO
    _registrar_auditoria(
        col_auditoria,
        quem=admin_id,
        alvo=alvo_id,
        nivel_anterior=nivel_anterior,
        nivel_novo=novo_nivel,
        resultado=resultado,
        motivo=None,
    )
    print(
        f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> OK. commit. "
        f"{alvo['nome']}: {nivel_anterior} -> {novo_nivel}"
    )
    return {"resultado": resultado}


def _registrar_auditoria(
    col_auditoria,
    quem: int,
    alvo: int,
    nivel_anterior,
    nivel_novo: int,
    resultado: Resultado,
    motivo: str | None,
) -> None:
    """
    Grava documento de auditoria no MongoDB.
    Executado SEMPRE — sucesso ou falha — para cumprir o requisito A09:
    um ataque que não deixa rastro é um ataque invisível.
    """
    doc = {
        "quem":            quem,
        "alvo":            alvo,
        "nivel_anterior":  nivel_anterior,
        "nivel_novo":      nivel_novo,
        "resultado":       resultado.value,
        "motivo_recusa":   motivo,
        "timestamp":       datetime.now(tz=timezone.utc),
    }
    col_auditoria.insert_one(doc)


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 4 — Transação com Trilha de Auditoria")
    print("=" * 72)

    with mysql_conn() as conn_mysql, mongo_client() as client_mongo:
        setup_mysql(conn_mysql)

        db_mongo     = client_mongo[os.environ.get("MONGO_DB", "seguranca")]
        col_auditoria = db_mongo["auditoria"]
        col_auditoria.drop()     # limpa para idempotência

        print("\n--- Sequência de alterações ---")
        alterar_nivel(1, 2, 4,  conn_mysql, col_auditoria)   # OK
        alterar_nivel(2, 3, 5,  conn_mysql, col_auditoria)   # sem privilégio
        alterar_nivel(1, 1, 9,  conn_mysql, col_auditoria)   # auto-promoção
        alterar_nivel(1, 99, 3, conn_mysql, col_auditoria)   # alvo inexistente

        print("\n--- Trilha de auditoria ---")
        total    = col_auditoria.count_documents({})
        recusados = col_auditoria.count_documents({"resultado": "RECUSADO"})
        print(f"db.auditoria.count_documents({{}}) -> {total} (esperado: 4)")
        print(f"db.auditoria.count_documents({{\"resultado\":\"RECUSADO\"}}) -> {recusados} (esperado: 3)")

        print("\nDocumentos na trilha:")
        for doc in col_auditoria.find({}, {"_id": 0, "timestamp": 0}):
            print(f"  {doc}")
