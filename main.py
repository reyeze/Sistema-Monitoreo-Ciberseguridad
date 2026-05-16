import platform
import socket


def mostrar_informacion_sistema():
    """Muestra datos básicos del equipo para el monitoreo inicial."""
    hostname = socket.gethostname()
    ip_local = socket.gethostbyname(hostname)
    sistema = platform.system()

    print("--- Sistema de Monitoreo de Ciberseguridad ---")
    print(f"Equipo: {hostname}")
    print(f"Dirección IP: {ip_local}")
    print(f"Sistema Operativo: {sistema}")
    print("Estado: Escáner listo y operativo.")


if __name__ == "__main__":
    mostrar_informacion_sistema()
