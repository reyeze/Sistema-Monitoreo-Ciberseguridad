"""
Módulo de Persistencia y Acceso a Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script actúa como una capa de abstracción para la interacción con la base de datos.
Provee las funciones necesarias para registrar la telemetría y eventos de seguridad
generados por los sensores, asegurando la integridad transaccional.
"""

"""
Módulo de Persistencia y Acceso a Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad
"""

import sqlite3
import os
import logging

# Configuración de mensajes en terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Ruta de la base de datos
DIRECTORIO_BASE = os.path.dirname(__file__)
RUTA_DB = os.path.join(DIRECTORIO_BASE, '..', 'data', 'ciberseguridad.db')

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
# FUNCIONES DEL SENSOR DE INTEGRIDAD (Tu código original)
# =====================================================================

# Función para guardar o actualizar el hash original (Línea base)
def guardar_hash_base(nombre_archivo, hash_valor):
    conn = sqlite3.connect(RUTA_DB) # Usamos RUTA_DB en lugar de 'seguridad_monitor.db'
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

# Función para registrar alertas cuando el hash cambia
def registrar_alerta_integridad(nombre_archivo):
    conn = sqlite3.connect(RUTA_DB)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alertas
                      (id INTEGER PRIMARY KEY, mensaje TEXT, fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute("INSERT INTO alertas (mensaje) VALUES (?)", (f"Alteración detectada en: {nombre_archivo}",))
    conn.commit()
    conn.close()

# === BLOQUE DE PRUEBA DE INTEGRACIÓN ===
if __name__ == "__main__":
    logging.info("Iniciando prueba de lógica de persistencia...")

    # Simulación 1: El Escáner TCP detecta un puerto peligroso abierto
    registrar_evento(
        id_modulo=1,
        descripcion_evento="Detección de puerto 445 (SMB) expuesto en la red local.",
        nivel_riesgo="Alto",
        evidencia_tecnica="Puerto: 445 | Estado: OPEN | Protocolo: TCP"
    )

    logging.info("Pruebas de persistencia finalizadas exitosamente.")

    # Cambio de prueba para verificar integridad