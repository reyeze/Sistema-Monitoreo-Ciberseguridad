"""
Módulo de Inicialización de Base de Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script se encarga de construir el esquema físico de la base de datos (SQLite3).
Crea las tablas relacionales necesarias e inserta los catálogos base para que
el sistema pueda operar correctamente desde su primera ejecución.
"""

import sqlite3
import os
import logging

# 1. Configuración para mostrar mensajes en la terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# 2. Definición de rutas relativas
DIRECTORIO_BASE = os.path.dirname(__file__)
RUTA_DB = os.path.join(DIRECTORIO_BASE, '..', 'data', 'ciberseguridad.db')

def preparar_entorno():
    """Valida y crea el directorio '/data' si no existe."""
    carpeta_datos = os.path.dirname(RUTA_DB)
    os.makedirs(carpeta_datos, exist_ok=True)

def inicializar_base_datos():
    """
    Se conecta al motor SQLite3, aplica restricciones arquitectónicas
    y ejecuta las sentencias DDL (Data Definition Language).
    """
    preparar_entorno()

    # El uso de 'with' (Manejador de Contexto) garantiza que la base de datos
    # se cierre de forma segura al terminar, incluso si ocurre un error.
    try:
        with sqlite3.connect(RUTA_DB) as conexion:
            cursor = conexion.cursor()

            # Activar integridad referencial estricta
            cursor.execute("PRAGMA foreign_keys = ON;")

            # --- CREACIÓN DE ESQUEMA RELACIONAL ---

            # Tabla 1: Catálogo de sensores (Módulos)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MODULOS (
                    id_modulo INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre_modulo TEXT NOT NULL,
                    descripcion TEXT NOT NULL,
                    activo INTEGER DEFAULT 1
                )
            ''')

            # Tabla 2: Parámetros dinámicos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS CONFIGURACION (
                    id_config INTEGER PRIMARY KEY AUTOINCREMENT,
                    id_modulo INTEGER NOT NULL,
                    parametro TEXT NOT NULL,
                    valor_asignado TEXT NOT NULL,
                    FOREIGN KEY (id_modulo) REFERENCES MODULOS (id_modulo)
                )
            ''')

            # Tabla 3: Registro transaccional de incidentes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS EVENTOS_SEGURIDAD (
                    id_evento INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    id_modulo INTEGER NOT NULL,
                    descripcion_evento TEXT NOT NULL,
                    nivel_riesgo TEXT NOT NULL,
                    evidencia_tecnica TEXT,
                    FOREIGN KEY (id_modulo) REFERENCES MODULOS (id_modulo)
                )
            ''')

            # Tabla 4: Trazabilidad y seguimiento de resolución
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ALERTAS_RESOLUCION (
                    id_alerta INTEGER PRIMARY KEY AUTOINCREMENT,
                    id_evento INTEGER NOT NULL UNIQUE,
                    estado TEXT DEFAULT 'Pendiente',
                    fecha_revision DATETIME,
                    FOREIGN KEY (id_evento) REFERENCES EVENTOS_SEGURIDAD (id_evento)
                )
            ''')

            # --- POBLADO INICIAL (SEEDING) ---

            cursor.execute("SELECT COUNT(*) FROM MODULOS")
            if cursor.fetchone()[0] == 0:
                cursor.executemany('''
                    INSERT INTO MODULOS (nombre_modulo, descripcion, activo)
                    VALUES (?, ?, ?)
                ''', [
                    ('Escáner TCP', 'Monitoreo de puertos abiertos en la red local.', 1),
                    ('Monitor SHA-256', 'Vigilancia de integridad de archivos sensibles.', 1)
                ])
                logging.info("Catálogo de MÓDULOS inicializado con datos por defecto.")

            logging.info(f"Éxito: Base de datos construida correctamente en {RUTA_DB}")

    except sqlite3.Error as error_db:
        logging.error(f"Fallo en el motor de base de datos: {error_db}")
    except Exception as e:
        logging.error(f"Error inesperado en la ejecución: {e}")

# Bloque principal de ejecución
if __name__ == "__main__":
    logging.info("Iniciando despliegue de arquitectura de datos...")
    inicializar_base_datos()

