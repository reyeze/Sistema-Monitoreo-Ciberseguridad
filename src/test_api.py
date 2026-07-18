# ==============================================================================
# Proyecto: Sistema de Monitoreo de Riesgos de Ciberseguridad
# Archivo: src/test_api.py
# Descripción: Script de validación automática (Pruebas de Integración).
#              Comprueba que los endpoints de la API local (Flask) estén
#              respondiendo correctamente para garantizar la disponibilidad
#              de los datos antes de mostrarlos en el Dashboard.
# ==============================================================================

# Utilizamos urllib para usar librerías nativas de Python y no depender de
# instalaciones externas (como 'requests') en este entorno de pruebas.
import urllib.request

def ejecutar_pruebas():
    print("==================================================")
    print("  INICIANDO PRUEBAS AUTOMATIZADAS DE LA API")
    print("==================================================")

    # Lista de las rutas (endpoints) que alimentan nuestro Dashboard web
    endpoints = [
        "http://127.0.0.1:5000/api/sistema",
        "http://127.0.0.1:5000/api/puertos",
        "http://127.0.0.1:5000/api/alertas"
    ]

    pruebas_pasadas = True

    # Iteramos sobre cada ruta para simular peticiones como si fuéramos el navegador
    for url in endpoints:
        try:
            # Realizamos la petición HTTP GET a la ruta
            respuesta = urllib.request.urlopen(url)
            codigo = respuesta.getcode()

            # Si el código es 200, el estándar web indica que todo está "OK"
            if codigo == 200:
                print(f"[ ÉXITO ] La ruta {url} respondió correctamente (Status 200 OK).")
            else:
                print(f"[ FALLO ] La ruta {url} devolvió un código inusual: {codigo}")
                pruebas_pasadas = False

        except Exception as e:
            # Manejo de errores en caso de que el orquestador maestro no esté encendido
            print(f"[ ERROR ] Falla crítica de conexión en la ruta: {url}")
            print(f"          Detalle técnico: {e}")
            print("          Sugerencia: Verificar que main.py esté en ejecución.")
            pruebas_pasadas = False

    print("==================================================")
    if pruebas_pasadas:
        print("[+] RESULTADO FINAL: Todas las rutas operativas. Integración validada.")
    else:
        print("[-] RESULTADO FINAL: Se detectaron bloqueos en la comunicación.")
    print("==================================================")

if __name__ == "__main__":
    ejecutar_pruebas()