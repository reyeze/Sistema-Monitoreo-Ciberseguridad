import os
import hashlib
import db_manager # Tu adaptador controlado

# Definimos la ruta base del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Lista de archivos a vigilar
ARCHIVOS_A_MONITOREAR = [
    os.path.join(BASE_DIR, 'src', 'scanner_tcp.py'),
    os.path.join(BASE_DIR, 'src', 'db_manager.py')
]

def calcular_hash(ruta_archivo):

# ... tu código anterior ...
    print(f"DEBUG: Leyendo archivo en: {os.path.abspath(ruta_archivo)}") # <--- AGREGA ESTO
    # ... resto de tu código ...

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
        print(f"[ERROR] Falló el cálculo para {ruta_archivo}: {e}")
        return None

def iniciar_monitoreo():
    """
    Función que implementa la lógica de monitoreo:
    1. Calcula el hash actual.
    2. Consulta al adaptador (db_manager) el hash base.
    3. Compara y registra alertas si es necesario.
    """
    print("--- Iniciando monitoreo local de archivos ---")

    for ruta in ARCHIVOS_A_MONITOREAR:
        nombre = os.path.basename(ruta)
        hash_actual = calcular_hash(ruta)

        if hash_actual is None:
            continue

        # === AQUÍ AGREGAMOS DE VUELTA LOS PRINTS PARA LA TERMINAL ===
        print(f"[OK] Archivo analizado: {nombre}")
        print(f"     Hash SHA-256: {hash_actual}")


        # Usamos el adaptador para obtener el hash base
        hash_guardado = db_manager.obtener_hash_base(nombre)

        if hash_guardado is None:
            # CASO 1: Primera ejecución, guardamos línea base
            db_manager.guardar_hash_base(nombre, hash_actual)
            print(f"[INFO] Línea base creada para: {nombre}")

        elif hash_actual != hash_guardado:
            # CASO 2: Alteración detectada
            print(f"[ALERTA] ¡Integridad comprometida en {nombre}!")
            db_manager.registrar_alerta_integridad(nombre)

        else:
            # CASO 3: Todo normal
            print(f"[OK] {nombre} está intacto.")

if __name__ == "__main__":
    iniciar_monitoreo()