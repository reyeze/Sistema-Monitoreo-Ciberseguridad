# ==============================================================================
# Proyecto: Centro de Monitoreo Local
# Archivo: main.py (Orquestador)
# Descripción: Script principal para integrar e iniciar los módulos del sistema
#              (Escáner TCP y API Web) de forma concurrente.
# ==============================================================================

import os
import subprocess
import sys
import time

# 1. Detectar automáticamente la carpeta raíz del proyecto (ya que main.py está en la raíz)
DIRECTORIO_RAIZ = os.path.dirname(os.path.abspath(__file__))

def iniciar_sistema():
    print("==================================================")
    print("  INICIANDO SISTEMA DE MONITOREO - ITERACIÓN 11")
    print("==================================================")
    print(f"[*] Directorio base detectado: {DIRECTORIO_RAIZ}\n")

    # Lista para guardar los procesos y poder cerrarlos al final
    procesos = []

    try:
        # 1. Levantar el módulo de escaneo (Backend)
        print("[*] Iniciando el motor de escaneo de red (scanner_tcp.py)...")

        proceso_escaner = subprocess.Popen(
            [sys.executable, "src/scanner_tcp.py"],
            cwd=DIRECTORIO_RAIZ
        )
        procesos.append(proceso_escaner)

        # Hacemos una pausa de 2 segundos
        time.sleep(2)

        # 2. Levantar la API Flask y el Dashboard (Frontend)
        print("[*] Iniciando la API Web y servidor Flask (api.py)...")

        proceso_api = subprocess.Popen(
            [sys.executable, "src/api.py"],
            cwd=DIRECTORIO_RAIZ
        )
        procesos.append(proceso_api)

        print("\n==================================================")
        print("[+] Integración exitosa. Todos los módulos operando.")
        print("[+] Dashboard disponible en el puerto 5000.")
        print("[!] Para detener el sistema de forma segura presiona Ctrl + C")
        print("==================================================\n")

        # Bucle infinito para evitar que el script principal se cierre solo
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        # Esto captura cuando el usuario presiona Ctrl + C en la terminal
        print("\n[!] Interrupción manual detectada.")
        print("[-] Apagando módulos y cerrando procesos activos...")

        for p in procesos:
            p.terminate() # Detiene cada proceso limpiamente

        print("[+] Sistema apagado correctamente.")

if __name__ == "__main__":
    iniciar_sistema()