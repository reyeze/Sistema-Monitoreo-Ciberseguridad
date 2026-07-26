#!/bin/bash

echo "=================================================="
echo "   INICIALIZANDO SISTEMA DE MONITOREO LOCAL"
echo "=================================================="

# 1. Configurar estructura base de la BD
echo "[+] Ejecutando db_setup.py..."
python3 src/db_setup.py

# 2. Inicializar el gestor de base de datos
echo "[+] Ejecutando db_manager.py..."
python3 src/db_manager.py

# 3. Actualizar baseline de archivos
echo "[+] Ejecutando actualizar_baseline.py..."
python3 src/actualizar_baseline.py

# 4. Ejecutar escaneo de red inicial
echo "[+] Ejecutando scanner_tcp.py..."
python3 src/scanner_tcp.py

# 5. Levantar el monitor de archivos en segundo plano (opcional)
echo "[+] Iniciando file_monitor.py en segundo plano..."
python3 src/file_monitor.py &

# 6. Levantar la API y Dashboard web (proceso principal)
echo "[+] Iniciando servidor API en http://localhost:5000 ..."
python3 src/api.py