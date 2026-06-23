"""
Módulo de Pruebas Unitarias (Unit Testing)
Proyecto: Sistema de monitoreo de riesgos de ciberseguridad

Este script utiliza el framework 'unittest' para automatizar la validación
de las consultas a la base de datos y asegurar la integridad de la información.
"""

import unittest
import sqlite3
import os

# Definir la ruta exacta a la base de datos
DIRECTORIO_BASE = os.path.dirname(__file__)
# Si guardas este archivo en /src, la ruta a /data es '../data/ciberseguridad.db'
RUTA_DB = os.path.join(DIRECTORIO_BASE, '..', 'data', 'ciberseguridad.db')

class TestBaseDatos(unittest.TestCase):

    def test_existencia_db(self):
        """Verifica que el archivo físico de la base de datos exista."""
        self.assertTrue(os.path.exists(RUTA_DB), "El archivo ciberseguridad.db no fue encontrado.")

    def test_catalogos_inicializados(self):
        """Valida que la tabla MODULOS tenga los registros por defecto."""
        with sqlite3.connect(RUTA_DB) as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT COUNT(*) FROM MODULOS")
            total_modulos = cursor.fetchone()[0]

            # Esperamos que haya al menos 2 módulos (TCP y SHA-256)
            self.assertGreaterEqual(total_modulos, 2, "Los catálogos no se inicializaron correctamente.")

    def test_consulta_eventos(self):
        """Ejecuta una consulta SELECT para validar que se pueden recuperar alertas."""
        with sqlite3.connect(RUTA_DB) as conexion:
            cursor = conexion.cursor()
            # Consultamos los eventos ordenados por el más reciente
            cursor.execute("SELECT id_modulo, nivel_riesgo FROM EVENTOS_SEGURIDAD ORDER BY timestamp DESC LIMIT 1")
            ultimo_evento = cursor.fetchone()

            # Verificamos que la consulta no devuelva un valor vacío
            self.assertIsNotNone(ultimo_evento, "No se encontraron eventos en la base de datos. La tabla está vacía.")

if __name__ == '__main__':
    # Ejecuta todas las pruebas con un nivel de detalle
    print("--- Iniciando Suite de Pruebas Unitarias de Base de Datos ---")
    unittest.main(verbosity=2)