"""
Módulo de Inicialización de Base de Datos
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script se encarga de construir el esquema físico de la base de datos (SQLite3)
Crea las tablas relacionales necesarias e inserta los catálogos base para que
el sistema pueda operar correctamente.
"""

import sqlite3
import os
import logging

# 1. Configuración para mostrar mensajes en la terminal
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# 2. Definición de rutas absolutas dinámicas (Solución a bases de datos duplicadas)
DIRECTORIO_ACTUAL = os.path.dirname(os.path.abspath(__file__)) # Ruta de src/
DIRECTORIO_RAIZ = os.path.dirname(DIRECTORIO_ACTUAL)            # Sube un nivel a la raíz
RUTA_DB = os.path.join(DIRECTORIO_RAIZ, 'data', 'ciberseguridad.db')

def preparar_entorno():
    """Valida y crea el directorio 'data' en la raíz si no existe."""
    carpeta_datos = os.path.dirname(RUTA_DB)
    os.makedirs(carpeta_datos, exist_ok=True)
    logging.info(f"Directorio de datos verificado en: {carpeta_datos}")

def inicializar_base_datos():
    """
    Se conecta al motor SQLite3, aplica restricciones arquitectónicas
    y ejecuta las sentencias DDL (Data Definition Language).
    """
    preparar_entorno()

    # El uso de 'with' Manejador de Contexto garantiza que la base de datos
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

            # Tabla 5: Auditoría de API
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS LOGS_AUDITORIA (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            logging.info("Tabla LOGS_AUDITORIA asegurada.")

            # --- NUEVA TABLA: Registro de Alertas del Escáner ---
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS registro_alertas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tipo_alerta TEXT,
                    nivel_riesgo TEXT,
                    descripcion TEXT,
                    fecha DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            logging.info("Tabla registro_alertas asegurada.")

            # --- FIRMA DE AUTORÍA E INSTITUCIONES (EASTER EGG) ---
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS METADATOS_SISTEMA (
                    clave TEXT PRIMARY KEY,
                    valor TEXT
                )
            ''')

            cursor.execute('''
                INSERT OR IGNORE INTO METADATOS_SISTEMA (clave, valor)
                VALUES ('AUTORIA', 'Proyecto Institucional: Cenidet & Infotec | Desarrollo e Ingeniería: Carlos Eduardo Reyez Rivera | Contacto: reyez.carlos@gmail.com | 2026')
            ''')
            logging.info("Metadatos de autoría inyectados correctamente.")

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