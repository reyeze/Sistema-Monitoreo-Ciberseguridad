"""
Módulo de Persistencia y Acceso a Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script actúa como una capa de abstracción para la interacción con la base de datos.
Provee las funciones necesarias para registrar la telemetría y eventos de seguridad
generados por los sensores, asegurando la integridad transaccional y horaria.
"""

import sqlite3
import os
import logging
from datetime import datetime
from zoneinfo import ZoneInfo

# Configuración de mensajes en terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Función para obtener la hora local exacta (México) de forma multiplataforma
def obtener_tiempo_local():
    return datetime.now(ZoneInfo("America/Mexico_City")).strftime("%Y-%m-%d %H:%M:%S")

# Ruta de la base de datos (Dinámica y absoluta para evitar bases duplicadas)
DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_RAIZ = os.path.dirname(DIRECTORIO_ACTUAL)
RUTA_DB = os.path.join(DIRECTORIO_RAIZ, 'data', 'ciberseguridad.db')

# =====================================================================
# FUNCIONES DEL ESCÁNER TCP Y EVENTOS
# =====================================================================
def registrar_evento(id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica):
    """Inserta un nuevo evento de seguridad en la base de datos local con la hora local de México."""
    try:
        tiempo_actual = obtener_tiempo_local()
        with sqlite3.connect(RUTA_DB) as conexion:
            cursor = conexion.cursor()

            consulta = '''
                INSERT INTO EVENTOS_SEGURIDAD
                (timestamp, id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica)
                VALUES (?, ?, ?, ?, ?)
            '''
            valores = (tiempo_actual, id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica)
            cursor.execute(consulta, valores)
            conexion.commit()
            logging.info(f"Evento Registrado [Módulo {id_modulo}] - Riesgo: {nivel_riesgo} | Detalle: {descripcion_evento}")
    except sqlite3.Error as error_db:
        logging.error(f"Fallo crítico en la persistencia de datos: {error_db}")

# =====================================================================
# FUNCIONES DEL SENSOR DE INTEGRIDAD
# =====================================================================
def crear_tabla_integridad():
    """Asegura la creación de la tabla de integridad con columnas estandarizadas."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS integridad_archivos (
            archivo TEXT PRIMARY KEY,
            hash_sha256 TEXT,
            estado TEXT
        )
    ''')
    conn.commit()
    conn.close()

def guardar_hash_base(nombre_archivo, hash_valor):
    """Guarda o actualiza el hash inicial de un archivo (Línea base)."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS integridad_archivos (
            archivo TEXT PRIMARY KEY,
            hash_sha256 TEXT,
            estado TEXT
        )
    ''')
    cursor.execute('''
        INSERT OR REPLACE INTO integridad_archivos (archivo, hash_sha256, estado)
        VALUES (?, ?, ?)
    ''', (nombre_archivo, hash_valor, "Monitoreado (Hash OK)"))
    conn.commit()
    conn.close()

def obtener_hash_base(nombre_archivo):
    """Consulta el hash guardado previamente para un archivo específico."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS integridad_archivos (
            archivo TEXT PRIMARY KEY,
            hash_sha256 TEXT,
            estado TEXT
        )
    ''')
    cursor.execute("SELECT hash_sha256 FROM integridad_archivos WHERE archivo = ?", (nombre_archivo,))
    resultado = cursor.fetchone()
    conn.close()
    return resultado[0] if resultado else None

# =====================================================================
# FUNCIONES DE ALERTAS
# =====================================================================
def crear_tabla_alertas():
    """Crea la tabla unificada para registrar alertas de todos los módulos."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registro_alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo_alerta TEXT,
            nivel_riesgo TEXT,
            descripcion TEXT,
            fecha DATETIME
        )
    ''')
    conn.commit()
    conn.close()

def registrar_alerta(tipo, riesgo, descripcion):
    """Guarda una alerta crítica o alta detectada por el sistema con hora local exacta."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    crear_tabla_alertas()
    tiempo_actual = obtener_tiempo_local()
    cursor.execute('''
        INSERT INTO registro_alertas (tipo_alerta, nivel_riesgo, descripcion, fecha)
        VALUES (?, ?, ?, ?)
    ''', (tipo, riesgo, descripcion, tiempo_actual))
    conn.commit()
    conn.close()
    logging.warning(f"ALERTA REGISTRADA [{riesgo}]: {descripcion}")

# === BLOQUE DE PRUEBA DE INTEGRACIÓN ===
if __name__ == "__main__":
    logging.info("Iniciando prueba de lógica de persistencia...")

    # Creamos todas las tablas necesarias
    crear_tabla_alertas()
    crear_tabla_integridad()

    # Simulación 1: El Escáner TCP detecta un puerto peligroso con timestamp local
    registrar_evento(
        id_modulo=1,
        descripcion_evento="Detección de puerto 445 (SMB) expuesto en la red local.",
        nivel_riesgo="Alto",
        evidencia_tecnica="Puerto: 445 | Estado: OPEN | Protocolo: TCP"
    )

    # Simulación 2: Alerta unificada registrada con fecha local
    registrar_alerta("Red", "Alto", "Puerto abierto innecesario detectado: 445 (SMB)")

    logging.info("Pruebas de persistencia finalizadas exitosamente.")