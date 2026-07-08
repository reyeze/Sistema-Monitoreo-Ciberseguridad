# Imagen oficial de Python ligera como base
FROM python:3.11-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Archivo de dependenciaspara optimizar el caché de Docker
COPY requirements.txt .

# Instalamos las librerías necesarias Flask, etc.
RUN pip install --no-cache-dir -r requirements.txt

# Copia del resto de los archivos del proyecto al contenedor
COPY . .

# Puerto 5000 expuesto para API Flask
EXPOSE 5000

# Comando para ejecutar la API cuando inicie el contenedor
CMD ["python", "src/api.py"]