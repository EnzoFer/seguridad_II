import hashlib
import json
import os
from datetime import datetime

class Blockchain:
    def __init__(self):
        self.cadena = []
        self.crear_bloque_genesis()

    def agregar_bloque_genesis(self):
        bloque_genesis = {
            "index": 0,
            "timestamp": str(datetime.now()),
            "data": "Bloque génesis",
            "prev_hash": "0"
        }
        bloque_genesis["hash"] = self.calcular_hash(bloque_genesis)
        self.cadena.append(bloque_genesis)


    def crear_bloque_genesis(self):
        bloque_genesis = {
            "index": 0,
            "timestamp": str(datetime.now()),
            "data": "Bloque Génesis",
            "prev_hash": "0"
        }
        bloque_genesis["hash"] = self.calcular_hash(bloque_genesis)
        self.cadena.append(bloque_genesis)

    def agregar_bloque(self, data):
            # Verificamos si la cadena tiene bloques
        if not self.cadena:
            print("La cadena está vacía, añadiendo bloque génesis primero.")
            self.agregar_bloque_genesis()

        bloque_anterior = self.cadena[-1]  # Obtener el último bloque
        bloque = {
            "index": len(self.cadena),
            "timestamp": str(datetime.now()),
            "data": data,
            "prev_hash": bloque_anterior["hash"]
        }
        bloque["hash"] = self.calcular_hash(bloque)
        self.cadena.append(bloque)
        return bloque

    def calcular_hash(self, bloque):
        bloque_str = json.dumps(bloque, sort_keys=True).encode()
        return hashlib.sha256(bloque_str).hexdigest()

    def guardar_cadena(self):
        with open('blockchain.json', 'w') as file:
            json.dump(self.cadena, file, indent=4)

    def cargar_cadena(self):
        if os.path.exists('blockchain.json'):
            with open('blockchain.json', 'r') as file:
                self.cadena = json.load(file)

class Logger:
    def __init__(self, archivo='eventos_seguridad.txt'):
        self.archivo = archivo

    def registrar_evento(self, mensaje):
        with open(self.archivo, 'a') as file:
            file.write(f"{datetime.now()}: {mensaje}\n")
