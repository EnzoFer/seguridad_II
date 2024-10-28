import requests
import json
import time
import random

SERVER_URL = 'http://127.0.0.1:5000/api/auditoria'

def enviar_datos():
    # Simular lectura de un sensor
    datos = {
        "dispositivo": "sensor_temperatura",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "unidad": "C",
        "valor": round(random.uniform(15.0, 30.0), 2)  # Valor aleatorio entre 15.0 y 30.0
    }
    
    # Enviar datos a la API
    response = requests.post(SERVER_URL, json=datos)
    
    if response.status_code == 200:
        print("Datos enviados exitosamente:", response.json())
    else:
        print("Error al enviar datos:", response.status_code, response.text)

if __name__ == '__main__':
    while True:
        enviar_datos()
        time.sleep(5)  # Enviar datos cada 5 segundos
