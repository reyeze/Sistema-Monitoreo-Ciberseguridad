import os
from datetime import datetime
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'monitor.log')

def log(mensaje):
    """Escribe eventos en el log centralizado con la hora local exacta de México."""
    timestamp = datetime.now(ZoneInfo("America/Mexico_City")).strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{timestamp}] {mensaje}"

    # Añadimos encoding='utf-8' para evitar caracteres extraños en los acentos
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        f.write(f"{linea}\n")

    print(linea) # Visualización en tiempo real en la terminal