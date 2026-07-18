import os
import sqlite3
from datetime import datetime
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)

# ==========================================
# CONFIGURACIÓN BASE DE DATOS
# ==========================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'data', 'ciberseguridad.db')

def conectar_bd():
    conexion = sqlite3.connect(DB_PATH)
    conexion.row_factory = sqlite3.Row
    return conexion

# ==========================================
# FUNCIÓN DE AUDITORÍA (Guardar en TXT)
# ==========================================
def registrar_log_auditoria(endpoint):
    """Escribe en un archivo de texto dentro de la carpeta /data."""
    try:
        ruta_log = os.path.join(BASE_DIR, 'data', 'api_logs.txt')
        with open(ruta_log, "a") as f:
            fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{fecha}] Acceso al endpoint: {endpoint}\n")
    except Exception as e:
        print(f"[ERROR] No pude escribir en el archivo de log: {e}")

# ==========================================
# RUTAS DE LA API Y FRONTEND
# ==========================================

# Ruta principal que carga el Dashboard oscuro
@app.route('/')
def dashboard():
    return render_template('index.html')

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

        # Lógica de filtros y paginación
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

        # OPTIMIZACIÓN: Se agrega GROUP BY para eliminar repeticiones de la vista
        # y se ordena para mantener el evento más reciente arriba.
        consulta += " GROUP BY evidencia_tecnica ORDER BY timestamp DESC LIMIT ? OFFSET ?"
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

@app.route('/api/alertas')
def obtener_alertas():
    try:
        # Usar la misma ruta a tu base de datos (DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Traemos las últimas 10 alertas ordenadas de la más reciente a la más antigua
        cursor.execute("SELECT fecha_hora, tipo_alerta, nivel_riesgo, descripcion FROM registro_alertas ORDER BY fecha_hora DESC LIMIT 10")
        filas = cursor.fetchall()
        conn.close()

        lista_alertas = []
        for fila in filas:
            lista_alertas.append({
                "fecha": fila[0],
                "tipo": fila[1],
                "riesgo": fila[2],
                "descripcion": fila[3]
            })
        return jsonify(lista_alertas)
    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == '__main__':
    # Cambiamos 127.0.0.1 por 0.0.0.0 para que Docker permita conexiones externas
    app.run(debug=True, host='0.0.0.0', port=5000)