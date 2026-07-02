import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'ciberseguridad.db')

def limpiar_hashes_viejos():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Aquí usamos el nombre real que descubrimos
        cursor.execute("DELETE FROM integridad_archivos")

        conn.commit()
        conn.close()
        print("[EXITO] La tabla 'integridad_archivos' ha sido limpiada.")
        print("-> Ahora ejecuta 'python src/file_monitor.py' para crear la nueva línea base.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    limpiar_hashes_viejos()