from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO
from blockchain import Blockchain, Logger
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

blockchain = Blockchain()
logger = Logger()

ALERTA_UMBRAL = {"temperatura": (0, 50)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auditoria', methods=['POST'])
def recibir_datos():
    datos = request.json
    if not datos:
        return jsonify({"error": "No se enviaron datos"}), 400
    
    valor = datos.get("valor")
    tipo = datos.get("unidad")
    
    if tipo == "C" and (valor < ALERTA_UMBRAL["temperatura"][0] or valor > ALERTA_UMBRAL["temperatura"][1]):
        alerta = f"¡Alerta! Temperatura fuera de rango: {valor}°C"
        logger.registrar_evento(alerta)
        
        nuevo_bloque = blockchain.agregar_bloque(json.dumps(datos, sort_keys=True))
        blockchain.guardar_cadena()

        # Emitir alerta y nuevo bloque a los clientes conectados
        socketio.emit('alerta', {'mensaje': alerta})
        socketio.emit('new_block', {
            'index': nuevo_bloque['index'],
            'timestamp': nuevo_bloque['timestamp'],
            'data': nuevo_bloque['data'],
            'hash': nuevo_bloque['hash'],
            'prev_hash': nuevo_bloque['prev_hash']
        })
        
        return jsonify({"message": "Log guardado en la blockchain", "bloque": nuevo_bloque, "alerta": alerta}), 200
    
    logger.registrar_evento(f"Valor normal registrado: {valor}°C")
    nuevo_bloque = blockchain.agregar_bloque(json.dumps(datos, sort_keys=True))
    blockchain.guardar_cadena()
    
    # Emitir el nuevo bloque sin alerta
    socketio.emit('new_block', {
        'index': nuevo_bloque['index'],
        'timestamp': nuevo_bloque['timestamp'],
        'data': nuevo_bloque['data'],
        'hash': nuevo_bloque['hash'],
        'prev_hash': nuevo_bloque['prev_hash']
    })
    
    return jsonify({"message": "Log guardado en la blockchain", "bloque": nuevo_bloque}), 200

@app.route('/api/blockchain', methods=['GET'])
def obtener_blockchain():
    blockchain.cargar_cadena()
    return jsonify(blockchain.cadena), 200

@app.route('/api/logs', methods=['GET'])
def obtener_logs():
    try:
        with open('eventos_seguridad.txt', 'r') as file:
            logs = file.readlines()
        return jsonify(logs), 200
    except FileNotFoundError:
        return jsonify({"error": "No se encontraron logs"}), 404

@app.route('/api/limpiar', methods=['POST'])
def limpiar_registros():
    # Limpiar la blockchain en memoria y en archivo
    blockchain.cadena = []
    blockchain.guardar_cadena()

    # Limpiar archivo de logs
    open('eventos_seguridad.txt', 'w').close()

    return jsonify({"message": "Blockchain y logs limpiados exitosamente"}), 200

if __name__ == '__main__':
    blockchain.cargar_cadena()
    socketio.run(app, debug=True)
