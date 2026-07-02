"""
Módulo Sensor de Red (Escáner TCP y Monitor de Disponibilidad)
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script escanea un vector de puertos críticos y además verifica
la disponibilidad (UP/DOWN) de servicios esenciales en la red.
"""

import socket
import sys
import sqlite3
import os
from db_manager import registrar_evento
from logger import log # Módulo de logs

# Rutas y configuración
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'data', 'ciberseguridad.db')

# Configuración del escáner
if len(sys.argv) > 1:
    IP_OBJETIVO = sys.argv[1]
else:
    IP_OBJETIVO = '127.0.0.1'

PUERTOS_CRITICOS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    445: "SMB",
    3389: "RDP"
}

ID_MODULO_RED = 1

# --- FUNCIONES ---
def esta_activado(id_modulo):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT activo FROM MODULOS WHERE id_modulo = ?", (id_modulo,))
        resultado = cursor.fetchone()
        conn.close()
        return resultado[0] == 1 if resultado else False
    except Exception as e:
        log(f"Error al conectar con la base de datos: {e}")
        return False

def escanear_puertos():
    if not esta_activado(ID_MODULO_RED):
        log(f"[*] El módulo de red está DESACTIVADO. Saltando ejecución.")
        return

    log(f"Iniciando escaneo de seguridad en IP: {IP_OBJETIVO}")
    puertos_abiertos = 0

    for puerto, servicio in PUERTOS_CRITICOS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            if sock.connect_ex((IP_OBJETIVO, puerto)) == 0:
                log(f"[!] ALERTA: Puerto {puerto} ({servicio}) EXPUESTO.")
                puertos_abiertos += 1
                descripcion = f"Detección de puerto {puerto} ({servicio}) abierto."
                evidencia = f"IP: {IP_OBJETIVO} | Puerto: {puerto} | Estado: OPEN"
                registrar_evento(ID_MODULO_RED, descripcion, "Alto", evidencia)
        except Exception:
            pass
        finally:
            sock.close()
    log(f"--- Escaneo listo. Puertos abiertos: {puertos_abiertos} ---")

def monitor_endpoint(host, puerto):
    log(f"Sondeo de disponibilidad para {host}:{puerto}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        resultado = sock.connect_ex((host, puerto))
        sock.close()
        if resultado == 0:
            log(f"[UP] El servicio en {host}:{puerto} está OPERATIVO.")
        else:
            log(f"[DOWN] El servicio en {host}:{puerto} NO RESPONDE.")
    except Exception as e:
        log(f"[DOWN] Error al sondear {host}:{puerto} - {e}")

if __name__ == '__main__':
    escanear_puertos()
    print("\n--- Iniciando Monitoreo de Disponibilidad ---")
    monitor_endpoint(IP_OBJETIVO, 80)
    monitor_endpoint("8.8.8.8", 53)