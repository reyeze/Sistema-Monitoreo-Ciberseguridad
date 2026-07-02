import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'ciberseguridad.db')

def resetear_hashes_integridad():
    """Limpia la tabla de hashes para actualizar la línea base."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Esta consulta le pregunta a SQLite cuáles son las tablas existentes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tablas = cursor.fetchall()
        print(f"Tablas encontradas en la BD: {tablas}")

        # Aquí verás el nombre real. Si el nombre correcto es, por ejemplo, 'HASHES',
        # solo cambia 'INTEGRIDAD_HASHES' por ese nombre en la siguiente línea:
        # cursor.execute("DELETE FROM TU_TABLA_REAL")

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Error: {e}")