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

# Configuración profesional de mensajes en terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Definición de rutas relativas
DIRECTORIO_BASE = os.path.dirname(__file__)
RUTA_DB = os.path.join(DIRECTORIO_BASE, '..', 'data', 'ciberseguridad.db')

def registrar_evento(id_modulo, descripcion_evento, nivel_riesgo, evidencia_tecnica):
    """
    Inserta un nuevo evento de seguridad en la base de datos local.
    Utiliza consultas parametrizadas (?) para prevenir vulnerabilidades de Inyección SQL.
    """
    try:
        # El manejador 'with' asegura el cierre de la conexión pase lo que pase
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

    # Simulación 2: El Monitor de Integridad detecta un archivo modificado
    registrar_evento(
        id_modulo=2,
        descripcion_evento="Modificación no autorizada en archivo de configuración del sistema.",
        nivel_riesgo="Crítico",
        evidencia_tecnica="Archivo: /etc/hosts | Hash_Anterior: a1b2c3d4... | Hash_Nuevo: f9e8d7c6..."
    )

    logging.info("Pruebas de persistencia finalizadas exitosamente.")