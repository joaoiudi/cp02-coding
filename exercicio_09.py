"""
Exercício 9 — Rate limiting guiado por anomalia (Aulas 2, 4, 6 e 8/A09)
Registra acessos no MongoDB, agrega features por IP e usa IsolationForest
para bloquear IPs anômalos com 429 + Retry-After: 60.
"""

import os
import time
from datetime import datetime, timedelta, timezone
from threading import Lock

import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest
from flask import Flask, jsonify, request, g

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Estado compartilhado (thread-safe com Lock simples)
# ---------------------------------------------------------------------------

_lock_bloqueados = Lock()
_ips_bloqueados: dict[str, float] = {}   # ip -> timestamp_bloqueio (epoch)

BLOQUEIO_DURACAO_S = 60    # Retry-After: 60
JANELA_ANALISE_S   = 60    # janela para calcular req/min e taxa 4xx

# ---------------------------------------------------------------------------
# Conexão MongoDB
# ---------------------------------------------------------------------------

def mongo_col():
    client = MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))
    db     = client[os.environ.get("MONGO_DB", "seguranca")]
    return client, db["acessos"]


# ---------------------------------------------------------------------------
# Middleware de registro
# ---------------------------------------------------------------------------

@app.before_request
def registrar_inicio():
    """Grava início da requisição e salva o ObjectId para completar depois."""
    ip    = request.remote_addr or "desconhecido"
    rota  = request.path
    metodo = request.method
    ts    = datetime.now(tz=timezone.utc)

    # Verificação de bloqueio ANTES de processar a rota
    with _lock_bloqueados:
        bloqueio_ts = _ips_bloqueados.get(ip)
    if bloqueio_ts and time.time() - bloqueio_ts < BLOQUEIO_DURACAO_S:
        g.bloqueado = True
        return

    g.bloqueado = False

    client, col = mongo_col()
    resultado = col.insert_one({
        "ip":      ip,
        "rota":    rota,
        "metodo":  metodo,
        "timestamp": ts,
        "status":  None,   # completado em after_request
    })
    client.close()
    g.acesso_id = resultado.inserted_id


@app.after_request
def registrar_fim(response):
    """Completa o documento de acesso com o status code retornado."""
    if getattr(g, "bloqueado", False):
        response.headers["Retry-After"] = str(BLOQUEIO_DURACAO_S)
        # Retorna 429 diretamente (o before_request já fez return)
        return response

    acesso_id = getattr(g, "acesso_id", None)
    if acesso_id is None:
        return response

    try:
        client, col = mongo_col()
        col.update_one(
            {"_id": acesso_id},
            {"$set": {"status": response.status_code}},
        )
        client.close()
    except Exception as e:
        app.logger.error("Erro ao atualizar registro de acesso: %s", e)

    return response


# ---------------------------------------------------------------------------
# Bloqueio 429 — retorna antes da rota ser processada
# ---------------------------------------------------------------------------

@app.before_request
def checar_bloqueio():
    ip = request.remote_addr or "desconhecido"
    with _lock_bloqueados:
        bloqueio_ts = _ips_bloqueados.get(ip)
    if bloqueio_ts and time.time() - bloqueio_ts < BLOQUEIO_DURACAO_S:
        resp = jsonify({"erro": "muitas requisições"})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(BLOQUEIO_DURACAO_S)
        return resp


# ---------------------------------------------------------------------------
# Extração de features por IP (via agregação MongoDB)
# ---------------------------------------------------------------------------

def extrair_features_por_ip(janela_s: int = JANELA_ANALISE_S) -> dict[str, list]:
    """
    Retorna {ip: [req_por_minuto, taxa_4xx, rotas_distintas]}
    A agregação é feita no banco — sem laço Python sobre os documentos.

    Comentário obrigatório sobre risco de bloqueio por anomalia:
    IsolationForest classifica como anômalo qualquer IP que fuja do padrão
    aprendido nos dados — mesmo um usuário legítimo com comportamento incomum
    (ex.: script de automação válido, crawler autorizado) pode ser classificado
    como anomalia, resultando em bloqueio indevido (falso positivo). Ao contrário
    de uma regra fixa ("bloquear se > 100 req/min"), a anomalia é relativa ao
    contexto atual: se todos os IPs tiverem tráfego alto, nenhum é anômalo.
    O risco é derrubar um usuário legítimo em um cenário de alta demanda,
    criando um DoS auto-infligido quando mais usuários estão ativos.
    """
    inicio = datetime.now(tz=timezone.utc) - timedelta(seconds=janela_s)

    client, col = mongo_col()
    pipeline = [
        {"$match": {"timestamp": {"$gte": inicio}, "status": {"$ne": None}}},
        {"$group": {
            "_id":           "$ip",
            "total_reqs":    {"$sum": 1},
            "reqs_4xx":      {"$sum": {"$cond": [
                {"$and": [{"$gte": ["$status", 400]}, {"$lt": ["$status", 500]}]}, 1, 0
            ]}},
            "rotas_distintas": {"$addToSet": "$rota"},
        }},
    ]
    resultados = list(col.aggregate(pipeline))
    client.close()

    features_por_ip: dict[str, list] = {}
    for r in resultados:
        ip           = r["_id"]
        total        = r["total_reqs"]
        reqs_4xx     = r["reqs_4xx"]
        n_rotas      = len(r["rotas_distintas"])
        req_por_min  = round(total / (janela_s / 60), 2)
        taxa_4xx     = round(reqs_4xx / total, 4) if total > 0 else 0.0
        features_por_ip[ip] = [req_por_min, taxa_4xx, n_rotas]

    return features_por_ip


# ---------------------------------------------------------------------------
# Análise com IsolationForest
# ---------------------------------------------------------------------------

def analisar_e_bloquear() -> dict[str, str]:
    """
    Extrai features, treina IsolationForest e bloqueia IPs anômalos.
    Retorna um relatório de status por IP.
    """
    features_por_ip = extrair_features_por_ip()

    if len(features_por_ip) < 2:
        return {}   # IsolationForest precisa de pelo menos 2 amostras

    ips     = list(features_por_ip.keys())
    X       = np.array([features_por_ip[ip] for ip in ips])

    clf = IsolationForest(contamination=0.2, random_state=42)
    clf.fit(X)
    previsoes = clf.predict(X)   # -1 = anômalo, 1 = normal

    relatorio: dict[str, str] = {}
    agora = time.time()

    for i, ip in enumerate(ips):
        req_min, taxa_4xx, n_rotas = features_por_ip[ip]
        if previsoes[i] == -1:
            with _lock_bloqueados:
                _ips_bloqueados[ip] = agora
            status = "ANOMALIA -> bloqueado"
        else:
            status = "normal"
        relatorio[ip] = (
            f"[{req_min:6.1f} req/min | 4xx {taxa_4xx:.2f} | {n_rotas} rota(s)] -> {status}"
        )

    return relatorio


# ---------------------------------------------------------------------------
# Rotas de demonstração
# ---------------------------------------------------------------------------

@app.route("/api/ping")
def ping():
    return jsonify({"status": "ok"}), 200


@app.route("/api/analise")
def analise():
    """Dispara a análise de anomalias e retorna o relatório."""
    relatorio = analisar_e_bloquear()
    print("\n=== Análise de acessos ===")
    for ip, status in relatorio.items():
        print(f"{ip:<20} {status}")
    return jsonify(relatorio), 200


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 9 — Rate Limiting por Anomalia (IsolationForest)")
    print("Servidor em http://localhost:5009")
    print()
    print("Roteiro de teste (execute teste_ex09.py em paralelo):")
    print("  python teste_ex09.py   # simula IP normal e IP hostil")
    print("  GET /api/analise       # dispara IsolationForest e bloqueia")
    print("=" * 72)
    print()
    print("# Risco de bloquear por anomalia vs. regra fixa:")
    print("# IsolationForest classifica pela distância ao padrão do grupo atual.")
    print("# Se todos os IPs têm tráfego alto (pico de acesso legítimo), nenhum")
    print("# é anômalo — o modelo adapta o limiar. O risco é o falso positivo:")
    print("# um usuário legítimo com comportamento estatisticamente incomum")
    print("# (automação válida, download grande) pode ser bloqueado, causando")
    print("# um DoS auto-infligido exatamente quando o sistema está sobrecarregado.")
    app.run(debug=False, port=5009)
