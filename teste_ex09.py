"""
Script de teste para o Exercício 9.
Simula um IP normal (5 requisições espaçadas) e um IP hostil
(60 requisições rápidas, maioria para rotas inexistentes).
Execute com o servidor do exercicio_09.py rodando.
"""

import time
import threading
import requests

BASE = "http://localhost:5009"


def ip_normal():
    """5 requisições espaçadas — comportamento legítimo."""
    session = requests.Session()
    session.headers["X-Forwarded-For"] = "192.168.1.10"
    for i in range(5):
        r = session.get(f"{BASE}/api/ping")
        print(f"[normal] req {i+1}: {r.status_code}")
        time.sleep(0.5)


def ip_hostil():
    """60 requisições em ~10s, maioria para rotas inexistentes."""
    session = requests.Session()
    session.headers["X-Forwarded-For"] = "185.220.101.1"
    rotas_ruins = [f"/rota_{i}" for i in range(40)]
    rotas_boas  = ["/api/ping"] * 20
    todas_rotas = rotas_ruins + rotas_boas

    for i, rota in enumerate(todas_rotas):
        try:
            r = session.get(f"{BASE}{rota}", timeout=2)
            if r.status_code == 429:
                print(f"[hostil] req {i+1} -> 429 BLOQUEADO! Retry-After: {r.headers.get('Retry-After')}")
                break
            print(f"[hostil] req {i+1} {rota}: {r.status_code}")
        except Exception as e:
            print(f"[hostil] req {i+1} erro: {e}")
        time.sleep(0.15)


if __name__ == "__main__":
    print("Iniciando simulação...")
    t1 = threading.Thread(target=ip_normal,  name="normal")
    t2 = threading.Thread(target=ip_hostil,  name="hostil")

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    print("\nDisparando análise de anomalias...")
    time.sleep(1)
    r = requests.get(f"{BASE}/api/analise")
    print("\n=== Análise de acessos ===")
    for ip, status in r.json().items():
        print(f"{ip:<20} {status}")

    print("\nTestando próxima requisição do IP hostil...")
    session = requests.Session()
    session.headers["X-Forwarded-For"] = "185.220.101.1"
    r = session.get(f"{BASE}/api/ping")
    print(f"Próxima requisição de 185.220.101.1 -> {r.status_code}")
    if r.status_code == 429:
        print(f"  Retry-After: {r.headers.get('Retry-After')}")
        print(f"  Body: {r.json()}")
