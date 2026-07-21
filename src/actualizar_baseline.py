import sqlite3
import os

# Configuración de la ruta de la base de datos
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'ciberseguridad.db')

def limpiar_hashes_viejos():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Elimina los registros anteriores para resetear la línea base
        cursor.execute("DELETE FROM integridad_archivos")

        conn.commit()
        conn.close()
        print("[ÉXITO] La tabla 'integridad_archivos' ha sido limpiada.")
        print("-> Ahora ejecuta 'python3 src/scanner_tcp.py' (o main.py) para registrar la nueva línea base.")

    except Exception as e:
        print(f"Error al limpiar la línea base: {e}")

if __name__ == "__main__":
    limpiar_hashes_viejos()