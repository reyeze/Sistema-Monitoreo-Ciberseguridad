# ==============================================================================
# Proyecto: Centro de Monitoreo Local
# Archivo: main.py (Orquestador)
# Descripción: Script principal para integrar e iniciar los módulos del sistema
#              (Escáner TCP y API Web) de forma concurrente.
# ==============================================================================

import subprocess
import sys
import time

def iniciar_sistema():
    print("==================================================")
    print("  INICIANDO SISTEMA DE MONITOREO - ITERACIÓN 10")
    print("==================================================")

    # Lista para guardar los procesos y poder cerrarlos al final
    procesos = []

    try:
        # 1. Levantar el módulo de escaneo (Backend)
        print("[*] Iniciando el motor de escaneo de red (scanner_tcp.py)...")

        # Usamos subprocess para que corra en segundo plano sin bloquear esta terminal
        proceso_escaner = subprocess.Popen([sys.executable, "src/scanner_tcp.py"])
        procesos.append(proceso_escaner)

        # Hacemos una pausa de 2 segundos para darle tiempo de inicializar la BD
        # antes de que la API intente leerla
        time.sleep(2)

        # 2. Levantar la API Flask y el Dashboard (Frontend)
        print("[*] Iniciando la API Web y servidor Flask (api.py)...")
        proceso_api = subprocess.Popen([sys.executable, "src/api.py"])
        procesos.append(proceso_api)

        print("\n==================================================")
        print("[+] Integración exitosa. Todos los módulos operando.")
        print("[+] Entorno local activo. Dashboard en: http://127.0.0.1:5000")
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