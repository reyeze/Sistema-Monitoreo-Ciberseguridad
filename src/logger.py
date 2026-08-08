import os
from datetime import datetime
from zoneinfo import ZoneInfo

# BASE_DIR apunta a la carpeta /src
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ruta exacta a la raíz del proyecto (/root/demo/monitor.log)
LOG_FILE = os.path.abspath(os.path.join(BASE_DIR, "..", "monitor.log"))

def log(mensaje):
    """Escribe eventos en el log centralizado sin detener la ejecución si hay fallos."""
    try:
        timestamp = datetime.now(ZoneInfo("America/Mexico_City")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback por si la zona horaria falla en algún entorno
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    linea = f"[{timestamp}] {mensaje}"

    # Bloque protegido: escribe en el log sin tumbar el sistema si falla el archivo
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{linea}\n")
    except Exception as e:
        print(f"[WARNING LOG] No se pudo escribir en el archivo: {e}")

    print(linea) # Muestra en consola
