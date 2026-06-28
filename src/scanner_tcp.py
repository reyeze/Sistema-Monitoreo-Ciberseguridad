"""
Módulo Sensor de Red (Escáner TCP)
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script escanea un vector de puertos críticos en el entorno de ejecución
(local o servidor remoto) y reporta los puertos expuestos a la capa de persistencia.
"""

import socket
import sys
import sqlite3
import os
import logging
from db_manager import registrar_evento

# Configuración de logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# --- CONFIGURACIÓN DE RUTA  ---
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

ID_MODULO_RED = 1  # ID del 'Escáner TCP' en la base de datos

# --- NUEVA FUNCIÓN: Control desde la Base de Datos ---
def esta_activado(id_modulo):
    """Verifica en la BD si el módulo está encendido (1) o apagado (0)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT activo FROM MODULOS WHERE id_modulo = ?", (id_modulo,))
        resultado = cursor.fetchone()
        conn.close()
        return resultado[0] == 1 if resultado else False
    except Exception as e:
        logging.error(f"Error al conectar con la base de datos: {e}")
        return False

def escanear_puertos():
    """Realiza un barrido TCP sobre la IP objetivo buscando puertos abiertos."""

    # NUEVO: Verificacion de  permisos antes de escanear
    if not esta_activado(ID_MODULO_RED):
        logging.warning(f"[*] El módulo de red (ID {ID_MODULO_RED}) está DESACTIVADO en la BD. Saltando ejecución.")
        return

    logging.info(f"Iniciando escaneo de seguridad en IP: {IP_OBJETIVO}")
    puertos_abiertos = 0

    for puerto, servicio in PUERTOS_CRITICOS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)

        try:
            # Intento de conexión
            resultado = sock.connect_ex((IP_OBJETIVO, puerto))

            if resultado == 0:
                logging.warning(f"[!] ALERTA: Puerto {puerto} ({servicio}) EXPUESTO.")
                puertos_abiertos += 1

                # Generar payload para la base de datos
                descripcion = f"Detección de puerto {puerto} ({servicio}) abierto y expuesto."
                evidencia = f"IP: {IP_OBJETIVO} | Puerto: {puerto} | Estado: OPEN"

                # Enviar alerta a persistencia (db_manager)
                registrar_evento(ID_MODULO_RED, descripcion, "Alto", evidencia)
        except Exception:
            pass
        finally:
            sock.close()

    logging.info(f"--- Escaneo listo. Puertos abiertos encontrados: {puertos_abiertos} ---")

if __name__ == '__main__':
    escanear_puertos()

# Simulación de inyección maliciosa
os.system("echo 'Datos extraídos' > log_secreto.txt")