import os
import hashlib
import sqlite3
import platform  # <-- Importado para detección del SO
import db_manager
import time
from logger import log  # Importamos el log centralizado
from datetime import datetime
from zoneinfo import ZoneInfo

# Función para obtener la hora local exacta (México) de forma multiplataforma
def obtener_tiempo_local():
    return datetime.now(ZoneInfo("America/Mexico_City")).strftime("%Y-%m-%d %H:%M:%S")

# Definimos la ruta base del proyecto de forma dinámica
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'ciberseguridad.db')

# Intervalo de tiempo para el monitoreo automático de integridad (en segundos)
INTERVALO_MONITOREO = 30

# ==========================================
# CONFIGURACIÓN MULTIPLATAFORMA SEGÚN EL SO
# ==========================================
if platform.system() == "Windows":
    RUTAS_DEFAULT = [
        r"C:\Windows\System32\drivers\etc\hosts"
    ]
else:
    RUTAS_DEFAULT = [
        "/etc/hosts"
    ]

# --- INICIO DE LECTURA MULTIPLATAFORMA ---
# Leemos los archivos a vigilar desde un archivo de texto externo
RUTA_CUSTOM = os.path.join(BASE_DIR, 'src', 'archivos_custom.txt')
ARCHIVOS_A_MONITOREAR = list(RUTAS_DEFAULT)

if os.path.exists(RUTA_CUSTOM):
    with open(RUTA_CUSTOM, "r") as f:
        for linea in f:
            nombre_archivo = linea.strip()
            # Ignoramos líneas vacías o comentarios que empiecen con #
            if nombre_archivo and not nombre_archivo.startswith("#"):
                # Si la línea ya es una ruta absoluta del sistema la usa tal cual,
                # si es un archivo relativo le anexa el path de src/
                if os.path.isabs(nombre_archivo):
                    ruta_completa = nombre_archivo
                else:
                    ruta_completa = os.path.join(BASE_DIR, 'src', nombre_archivo)

                if ruta_completa not in ARCHIVOS_A_MONITOREAR:
                    ARCHIVOS_A_MONITOREAR.append(ruta_completa)
else:
    log(f"[ERROR] No se encontró el archivo de configuración en: {RUTA_CUSTOM}")
# --- FIN DE LECTURA MULTIPLATAFORMA ---

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
            log(f"[-] Archivo no encontrado (verifica ruta): {ruta}")
            continue

        # Usamos el adaptador para obtener el hash base
        hash_guardado = db_manager.obtener_hash_base(nombre)

        if hash_guardado is None:
            db_manager.guardar_hash_base(nombre, hash_actual)
            log(f"[INFO] Línea base creada para: {nombre} | Hash: {hash_actual}")

        elif hash_actual != hash_guardado:
            # Ahora mostramos el comparativo para que sea auditable
            log(f"[ALERTA] ¡Integridad comprometida en {nombre}!")
            log(f"        Esperado: {hash_guardado}")
            log(f"        Actual:   {hash_actual}")
            # Aseguramos que el registro de alerta utilice la función del db_manager actualizada
            db_manager.registrar_alerta("Integridad", "Crítico", f"Modificación no autorizada en archivo: {nombre}")

        else:
            # Sincronizamos el estado de integridad en la BD para limpiar alertas previas
            db_manager.guardar_hash_base(nombre, hash_actual)
            log(f"[OK] {nombre} intacto. Hash: {hash_actual[:16]}...")

if __name__ == "__main__":
    log("=== INICIANDO SERVICIO CONTINUO DE MONITOR DE INTEGRIDAD ===")
    log(f"[*] Monitoreo autónomo activo. Intervalo de revisión: {INTERVALO_MONITOREO} segundos.")

    while True:
        try:
            iniciar_monitoreo()
            time.sleep(INTERVALO_MONITOREO)
        except KeyboardInterrupt:
            log("[!] Monitor de integridad detenido por el operador.")
            break
        except Exception as e:
            log(f"[ERROR] Ocurrió un fallo en el ciclo de integridad: {e}")
            time.sleep(INTERVALO_MONITOREO)