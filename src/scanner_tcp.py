"""
Módulo Principal de Monitoreo (Red e Integridad)
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script actúa como el núcleo de ejecución continua, escaneando puertos críticos,
verificando la disponibilidad de servicios esenciales y vigilando la integridad
de archivos sensibles de forma autónoma mediante sondeos periódicos.
"""

import socket
import sys
import sqlite3
import os
import platform
import hashlib
import time

from datetime import datetime
from zoneinfo import ZoneInfo

# Obtención automática de la hora local exacta (México) sin desfase UTC en contenedores ni sistemas operativos
def obtener_tiempo_local():
    return datetime.now(ZoneInfo("America/Mexico_City")).strftime("%Y-%m-%d %H:%M:%S")

# Importaciones de módulos internos
from db_manager import registrar_evento, registrar_alerta, guardar_hash_base, obtener_hash_base
from logger import log # Módulo de logs

# Rutas y configuración
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'data', 'ciberseguridad.db')

# Configuración del escáner
if len(sys.argv) > 1:
    IP_OBJETIVO = sys.argv[1]
else:
    IP_OBJETIVO = '192.168.3.4'

PUERTOS_CRITICOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    445: "SMB",
    3389: "RDP"
}

ID_MODULO_RED = 1
ID_MODULO_INT = 2 # ID para el módulo de integridad

# Intervalo de tiempo para el ciclo automático (en segundos)
INTERVALO_CICLO = 30

# --- FUNCIONES DE BASE DE DATOS Y ESTADO ---
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

# --- FUNCIONES DEL SENSOR DE RED ---
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

                # Guarda en la tabla general de iteraciones
                registrar_evento(ID_MODULO_RED, descripcion, "Alto", evidencia)

                # Guarda en la tabla específica de alertas
                registrar_alerta("Red", "Alto", descripcion)

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


# --- FUNCIONES SENSOR DE INTEGRIDAD ---
def obtener_archivos_a_vigilar():
    archivos_finales = []

    # 1. Archivo crítico por defecto según SO
    sistema = platform.system()
    if sistema == "Windows":
        archivos_finales.append(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        archivos_finales.append("/etc/hosts")

    # 2. Leer archivo de texto personalizado
    archivo_config = os.path.join(BASE_DIR, "archivos_custom.txt")

    if os.path.exists(archivo_config):
        with open(archivo_config, "r") as f:
            for linea in f:
                ruta = linea.strip()
                if ruta and not ruta.startswith("#"):
                    archivos_finales.append(ruta)
    else:
        with open(archivo_config, "w") as f:
            f.write("# SISTEMA DE MONITOREO - ARCHIVOS PERSONALIZADOS\n")
            f.write("# Escribe debajo la ruta absoluta de los archivos a vigilar (una por linea).\n")

    return archivos_finales

def monitorear_integridad():
    if not esta_activado(ID_MODULO_INT):
        log(f"[*] El módulo de integridad está DESACTIVADO. Saltando ejecución.")
        return

    log("Iniciando Monitor de Integridad de Archivos...")
    lista_archivos = obtener_archivos_a_vigilar()

    for ruta in lista_archivos:
        if not os.path.exists(ruta):
            log(f"[-] Archivo no encontrado (verifica ruta): {ruta}")
            continue

        sha256 = hashlib.sha256()
        try:
            with open(ruta, "rb") as f:
                while True:
                    bloque = f.read(4096)
                    if not bloque:
                        break
                    sha256.update(bloque)
                hash_actual = sha256.hexdigest()
        except PermissionError:
            log(f"[-] Error de permisos al intentar leer: {ruta}")
            continue

        hash_original = obtener_hash_base(ruta)

        if hash_original is None:
            log(f"[*] Guardando línea base inicial para: {ruta}")
            guardar_hash_base(ruta, hash_actual)

        elif hash_actual != hash_original:
            descripcion = f"Modificación no autorizada en archivo: {ruta}"
            log(f"[!] ALERTA CRÍTICA: {descripcion}")

            # Guardamos la alerta en ambas tablas para mantener consistencia
            registrar_evento(ID_MODULO_INT, descripcion, "Crítico", f"Archivo: {ruta} | Hash Alterado")
            registrar_alerta("Integridad", "Crítico", descripcion)
        else:
            log(f"[+] Integridad OK: {ruta}")

# --- EJECUCIÓN PRINCIPAL CONTINUA (AUTOMATIZADA) ---
if __name__ == '__main__':
    log("=== INICIANDO SERVICIO CONTINUO DE SENSORES DE CIBERSEGURIDAD ===")
    log(f"[*] Modo autónomo activado. Intervalo de sondeo: {INTERVALO_CICLO} segundos.")

    while True:
        try:
            log("\n--------------------------------------------------")
            log(">>> INICIANDO NUEVO CICLO DE MONITOREO AUTOMÁTICO")
            log("--------------------------------------------------")

            # 1. Sensor de Red
            escanear_puertos()

            log("\n--- Monitoreo de Disponibilidad de Endpoints ---")
            monitor_endpoint(IP_OBJETIVO, 80)
            monitor_endpoint("8.8.8.8", 53)

            log("\n--- Monitoreo de Integridad de Archivos ---")
            # 2. Sensor de Integridad
            monitorear_integridad()

            log("--------------------------------------------------")
            log(f"[*] Ciclo finalizado. Esperando {INTERVALO_CICLO}s para la siguiente revisión...")
            log("--------------------------------------------------\n")

        except KeyboardInterrupt:
            log("\n[!] Servicio detenido manualmente por el operador.")
            sys.exit(0)
        except Exception as error_ciclo:
            log(f"[!] Error crítico en el bucle de ejecución: {error_ciclo}")

        # Pausa autónoma antes de repetir el ciclo
        time.sleep(INTERVALO_CICLO)