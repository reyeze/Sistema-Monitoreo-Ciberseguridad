from flask import Flask, jsonify, request
import sqlite3
import os
from datetime import datetime # Importamos datetime para poner la fecha

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'ciberseguridad.db')

def conectar_bd():
    conexion = sqlite3.connect(DB_PATH)
    conexion.row_factory = sqlite3.Row
    return conexion

# --- FUNCIÓN DE AUDITORÍA (Guardar en TXT) ---
def registrar_log_auditoria(endpoint):
    """Escribe en un archivo de texto dentro de la carpeta /data."""
    try:
        # Construimos la ruta hacia la carpeta data
        ruta_log = os.path.join(BASE_DIR, 'data', 'api_logs.txt')

        # 'a' significa modo append (añadir al final)
        with open(ruta_log, "a") as f:
            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{fecha}] Acceso al endpoint: {endpoint}\n")

    except Exception as e:
        print(f"[ERROR] No pude escribir en el archivo de log: {e}")

# ==========================================
# RUTAS DE LA API
# ==========================================

@app.route('/api/sistema', methods=['GET'])
def estado_servidor():
    registrar_log_auditoria('/api/sistema')
    return jsonify({
        "estado": "operativo",
        "servicio": "API de Monitoreo Local"
    }), 200

@app.route('/api/puertos', methods=['GET'])
def obtener_puertos():
    registrar_log_auditoria('/api/puertos')
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()

        # ... (aquí va tu lógica de filtros) ...
        filtro_estado = request.args.get('estado')
        filtro_riesgo = request.args.get('nivel_riesgo')
        limite = request.args.get('cantidad', default=50, type=int)
        pagina = request.args.get('pagina', default=1, type=int)
        salto = (pagina - 1) * limite

        consulta = "SELECT * FROM eventos_seguridad WHERE 1=1"
        parametros = []

        if filtro_estado:
            consulta += " AND evidencia_tecnica LIKE ?"
            parametros.append(f"%{filtro_estado}%")
        if filtro_riesgo:
            consulta += " AND nivel_riesgo = ?"
            parametros.append(filtro_riesgo)

        consulta += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        parametros.extend([limite, salto])

        cursor.execute(consulta, parametros)
        registros = cursor.fetchall()
        conexion.close()

        return jsonify([dict(fila) for fila in registros]), 200

    except Exception as error:
        return jsonify({"error": "Fallo en consulta BD", "detalle": str(error)}), 500

@app.route('/api/integridad', methods=['GET'])
def obtener_integridad():
    registrar_log_auditoria('/api/integridad')
    try:
        conexion = conectar_bd()
        cursor = conexion.cursor()
        consulta = "SELECT * FROM integridad_archivos"
        cursor.execute(consulta)
        registros = cursor.fetchall()
        conexion.close()

        return jsonify([dict(fila) for fila in registros]), 200

    except Exception as error:
        return jsonify({"error": "No se pudo conectar a la base de datos", "detalle": str(error)}), 500

if __name__ == '__main__':
    # Cambiamos 127.0.0.1 por 0.0.0.0 para que Docker permita conexiones externas
    app.run(debug=True, host='0.0.0.0', port=5000)