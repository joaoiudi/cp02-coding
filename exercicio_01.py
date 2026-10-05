"""
Exercício 1 — Assistente de decisão de armazenamento (Aulas 1 e 8)
Lógica: sem ifs soltos — decisão via tabela de regras + motor de inferência.
"""

from dataclasses import dataclass
from typing import Callable


# ---------------------------------------------------------------------------
# Modelo de dados
# ---------------------------------------------------------------------------

@dataclass
class Regra:
    """Uma regra que, ao ser satisfeita, produz uma recomendação completa."""
    nome: str
    condicao: Callable[[dict], bool]
    banco: str
    cap: str
    justificativa: str
    risco_owasp: str


# ---------------------------------------------------------------------------
# Base de regras — a decisão vive aqui, não espalhada em ifs
# ---------------------------------------------------------------------------

REGRAS: list[Regra] = [
    Regra(
        nome="ACID + schema fixo: banco relacional obrigatório",
        condicao=lambda p: p["precisa_acid"] and p["schema_fixo"],
        banco="MySQL",
        cap="CP",
        justificativa=(
            "Dados que precisam de ACID e esquema rígido exigem MySQL: "
            "uma transação a meio (ex.: gravação de credencial sem commit) "
            "criaria um estado inconsistente que abriria falha de autenticação. "
            "O erro inaceitável aqui é dar acesso a quem não deveria — "
            "ou negar acesso a quem deveria ter — por causa de dados parcialmente gravados."
        ),
        risco_owasp=(
            "A07 — Falhas de Autenticação e Identificação: "
            "escolher um banco AP (eventual consistency) para credenciais significa "
            "que uma réplica desatualizada pode aceitar senha já expirada ou "
            "negar login com senha recém-alterada, comprometendo o controle de acesso."
        ),
    ),
    Regra(
        nome="Alta escala + tolera atraso: NoSQL favorito para telemetria",
        condicao=lambda p: p["escala_horizontal"] and p["tolera_atraso_de_consistencia"] and not p["dado_sensivel"],
        banco="MongoDB",
        cap="AP",
        justificativa=(
            "Telemetria de sensores gera volume explosivo e aceita que réplicas "
            "fiquem um segundo defasadas — perder 1 segundo de log é muito menos grave "
            "do que parar de aceitar eventos porque o nó primário ficou indisponível. "
            "O erro inaceitável aqui seria o sistema parar de ingerir eventos "
            "por exigir confirmação de todas as réplicas antes de retornar."
        ),
        risco_owasp=(
            "A09 — Falhas de Registro e Monitoramento: "
            "se o banco de logs fica indisponível por rigidez de consistência, "
            "eventos de ataque deixam de ser registrados — "
            "exatamente o que um atacante precisa para operar sem rastreamento."
        ),
    ),
    Regra(
        nome="Alta escala + dado sensível + sem tolerância a atraso: trilha de auditoria",
        condicao=lambda p: p["escala_horizontal"] and p["dado_sensivel"] and not p["tolera_atraso_de_consistencia"],
        banco="MongoDB",
        cap="CP",
        justificativa=(
            "Uma trilha de auditoria precisa escalar horizontalmente para não perder "
            "eventos em picos, mas jamais pode mostrar uma versão defasada: "
            "dois nós com trilhas divergentes significam que a evidência pode ser "
            "contestada juridicamente. O erro inaceitável é apresentar em juízo "
            "um log que não reflete o que de fato aconteceu."
        ),
        risco_owasp=(
            "A08 — Falhas de Integridade de Software e Dados: "
            "réplicas desatualizadas de uma trilha de auditoria permitem que "
            "um atacante interno negue ações registradas apenas na réplica atrasada, "
            "destruindo a cadeia de custódia digital."
        ),
    ),
    Regra(
        nome="ACID + schema fixo sem necessidade de escala: transacional puro",
        condicao=lambda p: p["precisa_acid"] and p["schema_fixo"] and not p["escala_horizontal"],
        banco="MySQL",
        cap="CP",
        justificativa=(
            "Carrinhos de licenças ou qualquer fluxo de compra exigem que "
            "débito e crédito aconteçam atomicamente: se o pagamento falhar, "
            "a licença não pode ser emitida, e vice-versa. "
            "O erro inaceitável é cobrar o cliente e não emitir a licença — "
            "ou emitir sem cobrar — por falta de transação atômica."
        ),
        risco_owasp=(
            "A05 — Controle de Acesso Quebrado: "
            "sem ACID, condições de corrida em emissão de licenças podem permitir "
            "que um usuário obtenha acesso não pago (race condition no checkout), "
            "equivalente a escalonamento de privilégio por exploração de estado inconsistente."
        ),
    ),
    Regra(
        nome="Schema fixo + escala + dado sensível + tolera atraso: cache de sessão",
        condicao=lambda p: p["escala_horizontal"] and p["dado_sensivel"] and p["tolera_atraso_de_consistencia"],
        banco="MongoDB",
        cap="AP",
        justificativa=(
            "Cache de sessões precisa de baixíssima latência em qualquer réplica — "
            "um token de sessão válido que chega ao nó errado pode ser rejeitado, "
            "expulsando o usuário sem motivo. Aceitar consistência eventual aqui é tolerável "
            "porque o erro inaceitável seria derrubar a experiência de autenticação "
            "de milhares de usuários por indisponibilidade de uma réplica primária."
        ),
        risco_owasp=(
            "A07 — Falhas de Autenticação e Identificação: "
            "se o nó de sessão ficar inacessível por rigidez CP, "
            "sessões válidas são negadas (DoS de autenticação); "
            "o dado sensível (token) deve ser criptografado em repouso "
            "para que a consistência eventual não exponha tokens em réplicas inseguras."
        ),
    ),
]

# Regra padrão (fallback) quando nenhuma outra se aplica
_REGRA_PADRAO = Regra(
    nome="Perfil ambíguo — padrão conservador",
    condicao=lambda p: True,
    banco="MySQL",
    cap="CP",
    justificativa=(
        "Perfil não mapeado nas regras conhecidas. "
        "A escolha conservadora é MySQL/CP: "
        "o erro inaceitável é assumir que consistência eventual é segura "
        "sem analisar o impacto de dados defasados naquele contexto."
    ),
    risco_owasp=(
        "A05 — Controle de Acesso Quebrado: "
        "decisões de acesso baseadas em dados eventualmente consistentes "
        "podem autorizar ações que já foram revogadas."
    ),
)


# ---------------------------------------------------------------------------
# Motor de inferência
# ---------------------------------------------------------------------------

def recomendar(perfil: dict) -> dict:
    """
    Recebe um perfil de conjunto de dados e retorna uma recomendação
    de banco, prioridade CAP, justificativa e risco OWASP.

    O motor avalia as regras em ordem de especificidade; a primeira
    regra satisfeita vence. Isso garante que a decisão seja rastreável:
    cada saída tem uma regra nomeada que a originou.
    """
    chaves_obrigatorias = {
        "schema_fixo", "precisa_acid", "escala_horizontal",
        "tolera_atraso_de_consistencia", "dado_sensivel",
    }
    ausentes = chaves_obrigatorias - perfil.keys()
    if ausentes:
        raise ValueError(f"Perfil incompleto — chaves ausentes: {ausentes}")

    for regra in REGRAS:
        if regra.condicao(perfil):
            return {
                "banco": regra.banco,
                "cap": regra.cap,
                "justificativa": regra.justificativa,
                "risco_owasp": regra.risco_owasp,
                "_regra_aplicada": regra.nome,   # rastreabilidade interna
            }

    # Nenhuma regra específica casou — aplica fallback
    return {
        "banco": _REGRA_PADRAO.banco,
        "cap": _REGRA_PADRAO.cap,
        "justificativa": _REGRA_PADRAO.justificativa,
        "risco_owasp": _REGRA_PADRAO.risco_owasp,
        "_regra_aplicada": _REGRA_PADRAO.nome,
    }


# ---------------------------------------------------------------------------
# Execução e saída formatada
# ---------------------------------------------------------------------------

perfis = {
    "credenciais_do_SOC": {
        "schema_fixo": True, "precisa_acid": True,
        "escala_horizontal": False, "tolera_atraso_de_consistencia": False,
        "dado_sensivel": True,
    },
    "telemetria_de_sensores": {
        "schema_fixo": False, "precisa_acid": False,
        "escala_horizontal": True, "tolera_atraso_de_consistencia": True,
        "dado_sensivel": False,
    },
    "trilha_de_auditoria": {
        "schema_fixo": False, "precisa_acid": False,
        "escala_horizontal": True, "tolera_atraso_de_consistencia": False,
        "dado_sensivel": True,
    },
    "carrinho_de_licencas": {
        "schema_fixo": True, "precisa_acid": True,
        "escala_horizontal": False, "tolera_atraso_de_consistencia": False,
        "dado_sensivel": False,
    },
    "cache_de_sessoes": {
        "schema_fixo": True, "precisa_acid": False,
        "escala_horizontal": True, "tolera_atraso_de_consistencia": True,
        "dado_sensivel": True,
    },
}

if __name__ == "__main__":
    print("=" * 72)
    print("EXERCÍCIO 1 — Assistente de Decisão de Armazenamento")
    print("=" * 72)

    for nome_perfil, perfil in perfis.items():
        rec = recomendar(perfil)
        print(f"\n📋 Perfil: {nome_perfil}")
        print(f"   Banco : {rec['banco']}  |  CAP: {rec['cap']}")
        print(f"   Regra : {rec['_regra_aplicada']}")
        print(f"   Justificativa:")
        # Quebra o texto em linhas para leitura confortável
        palavras = rec["justificativa"].split()
        linha = "     "
        for palavra in palavras:
            if len(linha) + len(palavra) + 1 > 72:
                print(linha)
                linha = "     " + palavra + " "
            else:
                linha += palavra + " "
        print(linha)
        print(f"   Risco OWASP:")
        palavras = rec["risco_owasp"].split()
        linha = "     "
        for palavra in palavras:
            if len(linha) + len(palavra) + 1 > 72:
                print(linha)
                linha = "     " + palavra + " "
            else:
                linha += palavra + " "
        print(linha)
