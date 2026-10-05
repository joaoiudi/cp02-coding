"""
Exercício 3 — Retenção e janela temporal (Aula 2)
Cria coleção eventos com índice TTL (7 dias), popula 200 eventos
espalhados em 24 horas e agrega falhas por hora do dia.
"""

import os
import random
from datetime import datetime, timedelta, timezone

from pymongo import MongoClient, ASCENDING


# ---------------------------------------------------------------------------
# Conexão
# ---------------------------------------------------------------------------

def mongo_client():
    uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    return MongoClient(uri)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TIPOS_EVENTO = ["FALHA_LOGIN", "PORT_SCAN", "BRUTE_FORCE", "XSS", "SQLI", "TIMEOUT"]
HOSTS        = [f"192.168.1.{i}" for i in range(10, 30)]


def gerar_eventos(n: int = 200) -> list[dict]:
    """
    Gera n eventos com timestamps distribuídos aleatoriamente
    nas últimas 24 horas. Todos com timezone UTC para compatibilidade
    com o operador $hour do MongoDB (que trabalha em UTC).
    """
    agora = datetime.now(tz=timezone.utc)
    eventos = []
    for _ in range(n):
        delta_segundos = random.randint(0, 86399)   # 0 a 23h59m59s atrás
        ts = agora - timedelta(seconds=delta_segundos)
        eventos.append({
            "tipo":      random.choice(TIPOS_EVENTO),
            "host":      random.choice(HOSTS),
            "timestamp": ts,
            "falha":     random.random() < 0.6,     # 60% são falhas
        })
    return eventos


def criar_colecao_com_ttl(db) -> None:
    """
    Cria a coleção `eventos` com índice TTL de 7 dias.
    O TTL é uma decisão de segurança: dados antigos acumulados
    ampliam a superfície de vazamento — quem acessa o banco
    em auditoria pode expor meses de comportamento de usuários.
    Automatizar a expiração garante que o princípio de minimização
    de dados (LGPD/GDPR) seja cumprido sem depender de processo manual.
    """
    # Remove coleção prévia para idempotência
    db.drop_collection("eventos")
    col = db["eventos"]

    col.create_index(
        [("timestamp", ASCENDING)],
        expireAfterSeconds=604800,   # 7 dias
        name="ttl_7dias",
    )
    print("[MongoDB] Coleção 'eventos' criada com índice TTL de 7 dias.")
    return col


def popular_eventos(col, n: int = 200) -> None:
    eventos = gerar_eventos(n)
    col.insert_many(eventos)
    print(f"[MongoDB] {n} eventos inseridos.")


# ---------------------------------------------------------------------------
# Agregação: distribuição de falhas por hora do dia (janela de 24 h)
# ---------------------------------------------------------------------------

def agregar_falhas_por_hora(col) -> list[dict]:
    """
    Pipeline de agregação:
      1. Filtra apenas eventos de falha na janela das últimas 24 horas.
      2. Agrupa por hora UTC do campo timestamp.
      3. Ordena cronologicamente.
    A agregação é feita inteiramente no banco — sem laço Python.
    """
    agora  = datetime.now(tz=timezone.utc)
    inicio = agora - timedelta(hours=24)

    pipeline = [
        # Etapa 1 — janela temporal + filtro de falhas
        {"$match": {
            "falha":     True,
            "timestamp": {"$gte": inicio, "$lte": agora},
        }},
        # Etapa 2 — extrai hora UTC e conta
        {"$group": {
            "_id":   {"$hour": "$timestamp"},
            "total": {"$sum": 1},
        }},
        # Etapa 3 — ordena por hora
        {"$sort": {"_id": 1}},
    ]

    return list(col.aggregate(pipeline))


def barra_ascii(valor: int, maximo: int, largura: int = 30) -> str:
    proporcao = valor / maximo if maximo > 0 else 0
    n_blocos  = int(proporcao * largura)
    return "█" * n_blocos


def imprimir_histograma(resultados: list[dict]) -> None:
    if not resultados:
        print("Nenhuma falha encontrada na janela de 24 horas.")
        return

    maximo = max(r["total"] for r in resultados)
    hora_pico = max(resultados, key=lambda r: r["total"])

    print("\n=== Falhas por hora (últimas 24h) ===")
    for r in resultados:
        hora  = r["_id"]
        total = r["total"]
        barra = barra_ascii(total, maximo)
        pico_marker = "  <- pico" if hora == hora_pico["_id"] else ""
        print(f"{hora:02d}h | {barra} {total}{pico_marker}")

    print(f"\nHora de pico: {hora_pico['_id']:02d}h ({hora_pico['total']} falhas)")
    print("Índice TTL ativo: eventos com mais de 7 dias serão removidos automaticamente.")
    print()
    print(
        "# Por que TTL é uma decisão de SEGURANÇA e não só de disco:\n"
        "# Logs acumulados indefinidamente ampliam a janela de exposição em caso\n"
        "# de breach — um atacante que acessa o banco encontra histórico completo\n"
        "# de IPs, padrões de acesso e usuários, violando o princípio de minimização\n"
        "# de dados (LGPD Art. 6° e GDPR Art. 5°). O TTL limita o raio de impacto."
    )


def verificar_indice_ttl(col) -> None:
    indices = col.index_information()
    ttl_ativo = any(
        info.get("expireAfterSeconds") is not None
        for info in indices.values()
    )
    status = "ATIVO" if ttl_ativo else "NÃO ENCONTRADO"
    print(f"\n[Verificação] Índice TTL: {status}")
    for nome, info in indices.items():
        if "expireAfterSeconds" in info:
            print(f"  Índice '{nome}': expireAfterSeconds={info['expireAfterSeconds']}")


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 3 — Retenção e Janela Temporal")
    print("=" * 72)

    with mongo_client() as client:
        db  = client[os.environ.get("MONGO_DB", "seguranca")]
        col = criar_colecao_com_ttl(db)
        popular_eventos(col, n=200)

        resultados = agregar_falhas_por_hora(col)
        imprimir_histograma(resultados)
        verificar_indice_ttl(col)

        print(
            "\n⚠️  O MongoDB executa a varredura TTL a cada ~60s;\n"
            "    documentos expirados não desaparecem instantaneamente no teste."
        )
