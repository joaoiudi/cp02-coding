"""
Exercício 10 — app_vulneravel.py (laboratório apenas)
ATENÇÃO: Este código contém falhas INTENCIONAIS para demonstração.
Use exclusivamente contra a sua cópia local.
Lei 12.737/2012 — crimes cibernéticos.
"""

from flask import Flask, request, jsonify
import mysql.connector

app = Flask(__name__)
SENHA_MESTRA = "Cyber@2024"   # FALHA 1: segredo exposto em código (A02)


def db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="senha",        # FALHA 2: credencial hardcoded (A02)
        database="seguranca",
    )


@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    cur = db().cursor(dictionary=True)
    # FALHA 3: SQL Injection por f-string (A03)
    cur.execute(f"SELECT * FROM usuarios WHERE nome LIKE '%{nome}%'")
    # FALHA 4: coluna senha exposta na resposta (A02)
    return jsonify(cur.fetchall())


@app.route("/perfil")
def perfil():
    # FALHA 5: XSS refletido — entrada do usuário renderizada como HTML (A03)
    return f"<h1>Bem-vindo, {request.args.get('u','')}</h1>"


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    # FALHA 6: sem autenticação nem autorização (A01)
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    con.commit()
    return jsonify({"removido": uid})


@app.route("/api/relatorio")
def relatorio():
    cur = db().cursor()
    cur.execute("SELECT * FROM tabela_inexistente")
    # FALHA 7: exceção não tratada vaza traceback com nome de tabela (A05)
    return jsonify(cur.fetchall())


# FALHA 8 (AUSÊNCIA): nenhum header de segurança (CSP, X-Frame-Options etc.) (A05)
# FALHA 9 (AUSÊNCIA): nenhum registro de requisições/acessos (A09)

if __name__ == "__main__":
    # FALHA ADICIONAL: debug=True em produção expõe console interativo (A05)
    app.run(debug=True, host="0.0.0.0")
