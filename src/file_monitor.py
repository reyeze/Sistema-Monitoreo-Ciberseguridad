import os
import hashlib
import sqlite3
import db_manager
from logger import log  # Importamos el log centralizado

# Definimos la ruta base del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, '..', 'data', 'ciberseguridad.db')


# Lista de archivos a vigilar
ARCHIVOS_A_MONITOREAR = [
    os.path.join(BASE_DIR, 'src', 'scanner_tcp.py'),
    os.path.join(BASE_DIR, 'src', 'db_manager.py')
]

def calcular_hash(ruta_archivo):
    """Calcula el hash SHA-256 de un archivo."""
    if not os.path.exists(ruta_archivo):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            while True:
                bloque = f.read(4096)
                if not bloque: break
                sha256_hash.update(bloque)
        return sha256_hash.hexdigest()
    except Exception as e:
        log(f"[ERROR] Falló el cálculo para {ruta_archivo}: {e}")
        return None

def iniciar_monitoreo():
    log("--- Iniciando monitoreo local de archivos ---")
for ruta in ARCHIVOS_A_MONITOREAR:
        nombre = os.path.basename(ruta)
        hash_actual = calcular_hash(ruta)

        if hash_actual is None:
            continue

        # Usamos el adaptador para obtener el hash base
        hash_guardado = db_manager.obtener_hash_base(nombre)

        if hash_guardado is None:
            db_manager.guardar_hash_base(nombre, hash_actual)
            log(f"[INFO] Línea base creada para: {nombre} | Hash: {hash_actual}")

        elif hash_actual != hash_guardado:
            # Ahora mostramos el comparativo para que sea auditable
            log(f"[ALERTA] ¡Integridad comprometida en {nombre}!")
            log(f"         Esperado: {hash_guardado}")
            log(f"         Actual:   {hash_actual}")
            db_manager.registrar_alerta_integridad(nombre)

        else:
            # Aquí mostramos el hash solo en modo debug o si quieres verlo siempre
            log(f"[OK] {nombre} intacto. Hash: {hash_actual[:16]}...")