import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, 'monitor.log')

def log(mensaje):
    """Escribe eventos en el log centralizado."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{timestamp}] {mensaje}"

    # Añadimos encoding='utf-8' para evitar caracteres extraños en los acentos
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        f.write(f"{linea}\n")

    print(linea) # Visualización en tiempo real en la terminal