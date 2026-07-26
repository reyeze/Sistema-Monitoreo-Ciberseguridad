@echo off
echo ==================================================
echo    INICIALIZANDO SISTEMA DE MONITOREO LOCAL
echo ==================================================

:: 1. Configurar estructura base de la BD
echo [+] Ejecutando db_setup.py...
python src\db_setup.py

:: 2. Inicializar el gestor de base de datos
echo [+] Ejecutando db_manager.py...
python src\db_manager.py

:: 3. Actualizar baseline de archivos
echo [+] Ejecutando actualizar_baseline.py...
python src\actualizar_baseline.py

:: 4. Escaneo de red inicial
echo [+] Ejecutando scanner_tcp.py...
python src\scanner_tcp.py

:: 5. Levantar el monitor de archivos en paralelo
echo [+] Iniciando file_monitor.py en paralelo...
start cmd /k "python src\file_monitor.py"

:: 6. Levantar la API y Dashboard web
echo [+] Iniciando servidor API en http://localhost:5000 ...
python src\api.py

pause