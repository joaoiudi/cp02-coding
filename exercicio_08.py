"""
Exercício 8 — Modelo de ML servido por API, com métricas auditáveis (Aulas 2, 4, 6, 7)
POST /api/triagem          -> previsão de risco com validação de entrada
GET  /api/modelo/metricas  -> precisão, recall, F1 e matriz de confusão
Toda previsão válida é gravada no MongoDB (A09/A08).
"""

import os
from datetime import datetime, timezone

import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Dataset sintético
# Features: [falhas_login, portas_distintas, bytes_saida, hora_do_dia]
# Rótulo: 1 = alto risco, 0 = baixo risco
# ---------------------------------------------------------------------------

RANDOM_STATE = 42   # fixo para reprodutibilidade

np.random.seed(RANDOM_STATE)

# Amostras de ALTO risco (muitas falhas, muitas portas, muito tráfego, noturno)
alto_risco = np.column_stack([
    np.random.randint(5, 30, 200),        # falhas_login: 5-30
    np.random.randint(5, 20, 200),        # portas_distintas: 5-20
    np.random.randint(50000, 200000, 200), # bytes_saida: 50k-200k
    np.random.randint(0, 6, 200),         # hora_do_dia: meia-noite a 6h
])

# Amostras de BAIXO risco (poucas falhas, poucas portas, pouco tráfego, diurno)
baixo_risco = np.column_stack([
    np.random.randint(0, 3, 200),         # falhas_login: 0-2
    np.random.randint(1, 5, 200),         # portas_distintas: 1-4
    np.random.randint(100, 5000, 200),    # bytes_saida: 100-5k
    np.random.randint(8, 18, 200),        # hora_do_dia: 8h-17h
])

X = np.vstack([alto_risco, baixo_risco])
y = np.array([1] * 200 + [0] * 200)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)

# ---------------------------------------------------------------------------
# Treinamento
# ---------------------------------------------------------------------------

modelo = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
modelo.fit(X_train, y_train)

y_pred = modelo.predict(X_test)

METRICAS = {
    "precisao": round(precision_score(y_test, y_pred, zero_division=0), 4),
    "recall":   round(recall_score(y_test, y_pred, zero_division=0), 4),
    "f1":       round(f1_score(y_test, y_pred, zero_division=0), 4),
    "matriz":   confusion_matrix(y_test, y_pred).tolist(),
    # Acurácia OMITIDA propositalmente — ver aviso abaixo
    "aviso": (
        "A acurácia foi omitida desta API porque, em datasets desbalanceados, "
        "ela pode ser enganosa: um modelo que classifica tudo como 'baixo risco' "
        "pode ter 90% de acurácia em um dataset com 90% de negativos, mas recall=0 "
        "para ameaças reais — exatamente o pior resultado possível em segurança. "
        "Precisão e recall forçam a análise do trade-off entre falsos positivos e "
        "falsos negativos, que é o que importa para decisões de triagem."
    ),
}

N_FEATURES = 4   # [falhas_login, portas_distintas, bytes_saida, hora_do_dia]

# ---------------------------------------------------------------------------
# Conexão MongoDB (para auditoria de previsões)
# ---------------------------------------------------------------------------

def mongo_client():
    return MongoClient(os.environ.get("MONGO_URI", "mongodb://localhost:27017/"))


def gravar_previsao(features: list, risco: str, confianca: float) -> None:
    """Toda previsão válida é auditada no MongoDB (A09/A08)."""
    try:
        with mongo_client() as client:
            db  = client[os.environ.get("MONGO_DB", "seguranca")]
            col = db["previsoes"]
            col.insert_one({
                "features":   features,
                "risco":      risco,
                "confianca":  confianca,
                "timestamp":  datetime.now(tz=timezone.utc),
            })
    except Exception as e:
        app.logger.error("Falha ao auditar previsão: %s", e)
        # Não interrompe a resposta — auditoria não deve derrubar o serviço


# ---------------------------------------------------------------------------
# Validação de entrada
# ---------------------------------------------------------------------------

def validar_features(body: dict) -> tuple[list | None, str | None]:
    """
    Retorna (features, None) se válido, ou (None, mensagem_de_erro) se inválido.
    Entrada de modelo é entrada de usuário — validação obrigatória.
    """
    if not body or "features" not in body:
        return None, "campo 'features' obrigatório"

    features = body["features"]

    if not isinstance(features, list):
        return None, "features deve ser uma lista"

    if len(features) != N_FEATURES:
        return None, f"esperadas {N_FEATURES} features, recebidas {len(features)}"

    for item in features:
        if not isinstance(item, (int, float)):
            return None, "features devem ser numéricas"

    return features, None


# ---------------------------------------------------------------------------
# Rotas
# ---------------------------------------------------------------------------

@app.route("/api/triagem", methods=["POST"])
def triagem():
    body = request.get_json(silent=True)
    features, erro = validar_features(body or {})

    if erro:
        return jsonify({"erro": erro}), 400

    X_input = np.array([features])
    classe     = int(modelo.predict(X_input)[0])
    proba      = modelo.predict_proba(X_input)[0]
    confianca  = round(float(proba[classe]), 4)
    risco      = "alto" if classe == 1 else "baixo"

    # Auditoria ANTES de retornar (A09 — rastrear previsões do modelo)
    gravar_previsao(features, risco, confianca)

    return jsonify({"risco": risco, "confianca": confianca}), 200


@app.route("/api/modelo/metricas")
def metricas():
    return jsonify(METRICAS), 200


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 8 — Modelo de ML com API e Auditoria")
    print(f"Modelo treinado: {len(X_train)} amostras | Teste: {len(X_test)} amostras")
    print(f"Métricas: precisão={METRICAS['precisao']} recall={METRICAS['recall']} F1={METRICAS['f1']}")
    print("Servidor em http://localhost:5008")
    print("Testes:")
    print('  curl -X POST -H "Content-Type: application/json"')
    print('       -d \'{"features":[12,7,90000,3]}\' http://localhost:5008/api/triagem')
    print('  curl -X POST -H "Content-Type: application/json"')
    print('       -d \'{"features":[0,1,1200,14]}\' http://localhost:5008/api/triagem')
    print('  curl http://localhost:5008/api/modelo/metricas')
    print("=" * 72)
    app.run(debug=False, port=5008)
