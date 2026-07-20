"""
Módulo de Persistencia y Acceso a Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script actúa como una capa de abstracción para la interacción con la base de datos.
Provee las funciones necesarias para registrar la telemetría y eventos de seguridad
generados por los sensores, asegurando la integridad transaccional.
"""

import sqlite3
import os
import logging
from logger import log

# Configuración de mensajes en terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Ruta de la base de datos (Dinámica y absoluta para evitar bases duplicadas)
DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_RAIZ = os.path.dirname(DIRECTORIO_ACTUAL)
RUTA_DB = os.path.join(DIRECTORIO_RAIZ, 'data', 'ciberseguridad.db')

# =====================================================================
# FUNCIONES DEL ESCÁNER TCP
# =====================================================================
def registrar_evento(id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica):
    """Inserta un nuevo evento de seguridad en la base de datos local."""
    try:
        with sqlite3.connect(RUTA_DB) as conexion:
            cursor = conexion.cursor()
            consulta = '''
                INSERT INTO EVENTOS_SEGURIDAD
                (id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica)
                VALUES (?, ?, ?, ?)
            '''
            valores = (id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica)
            cursor.execute(consulta, valores)
            conexion.commit()
            logging.info(f"Evento Registrado [Módulo {id_modulo}] - Riesgo: {nivel_riesgo} | Detalle: {descripcion_evento}")
    except sqlite3.Error as error_db:
        logging.error(f"Fallo crítico en la persistencia de datos: {error_db}")

# =====================================================================
# FUNCIONES DEL SENSOR DE INTEGRIDAD
# =====================================================================

# Función para guardar o actualizar el hash original (Línea base)
def guardar_hash_base(nombre_archivo, hash_valor):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS integridad_archivos
                      (nombre TEXT PRIMARY KEY, hash_original TEXT)''')
    cursor.execute('''REPLACE INTO integridad_archivos (nombre, hash_original)
                      VALUES (?, ?)''', (nombre_archivo, hash_valor))
    conn.commit()
    conn.close()

# Función para obtener el hash original guardado
def obtener_hash_base(nombre_archivo):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    # Agregamos CREATE TABLE aquí por si se consulta antes de guardar algo
    cursor.execute('''CREATE TABLE IF NOT EXISTS integridad_archivos
                      (nombre TEXT PRIMARY KEY, hash_original TEXT)''')
    cursor.execute("SELECT hash_original FROM integridad_archivos WHERE nombre = ?", (nombre_archivo,))
    resultado = cursor.fetchone()
    conn.close()
    return resultado[0] if resultado else None

# =====================================================================
# NUEVAS FUNCIONES DE ALERTAS
# =====================================================================
def crear_tabla_alertas():
    """Crea la tabla unificada para registrar alertas de todos los módulos."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    # Alineado con la estructura de db_setup.py para mantener consistencia
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registro_alertas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo_alerta TEXT,
            nivel_riesgo TEXT,
            descripcion TEXT,
            fecha DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def registrar_alerta(tipo, riesgo, descripcion):
    """Guarda una alerta crítica o alta detectada por el sistema."""
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO registro_alertas (tipo_alerta, nivel_riesgo, descripcion)
        VALUES (?, ?, ?)
    ''', (tipo, riesgo, descripcion))
    conn.commit()
    conn.close()
    logging.warning(f"ALERTA REGISTRADA [{riesgo}]: {descripcion}")

# === BLOQUE DE PRUEBA DE INTEGRACIÓN ===
if __name__ == "__main__":
    logging.info("Iniciando prueba de lógica de persistencia...")

    crear_tabla_alertas()

    # Simulación 1: El Escáner TCP detecta un puerto peligroso
    registrar_evento(
        id_modulo=1,
        descripcion_evento="Detección de puerto 445 (SMB) expuesto en la red local.",
        nivel_riesgo="Alto",
        evidencia_tecnica="Puerto: 445 | Estado: OPEN | Protocolo: TCP"
    )

    # Simulación 2: Simulando la nueva alerta clasificada
    registrar_alerta("Red", "Alto", "Puerto abierto innecesario detectado: 445 (SMB)")

    logging.info("Pruebas de persistencia finalizadas exitosamente.")