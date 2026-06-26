from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import pyotp
import datetime
from bson.objectid import ObjectId

app = Flask(__name__)
CORS(app) # Para que Ionic no te marque error de CORS

# Conexión a MongoDB local
client = MongoClient('mongodb+srv://victorsolis2019:Tobivictor__11@cluster0.syaedri.mongodb.net/?appName=Cluster0')
db = client['QR']
coleccion_altas = db['Escaneo']

@app.route('/api/generar-alta', methods=['POST'])
def generar_alta():
    data = request.json
    servicio = data.get('servicio')
    cuenta = data.get('cuenta')

    # 1. El backend es quien DEBE generar la llave secreta única
    secreto_base32 = pyotp.random_base32()
    
    # 2. Creamos la URI para que el frontend genere el QR
    totp_uri = pyotp.totp.TOTP(secreto_base32).provisioning_uri(name=cuenta, issuer_name=servicio)

    # 3. Guardamos en MongoDB
    nuevo_registro = {
        "servicio": servicio,
        "cuenta": cuenta,
        "secreto": secreto_base32, # Guardamos el secreto para validar después
        "fecha": datetime.datetime.now(),
        "estado": "Pendiente"
    }
    resultado = coleccion_altas.insert_one(nuevo_registro)

    return jsonify({
        "id": str(resultado.inserted_id),
        "qr_uri": totp_uri,
        "mensaje": "Alta generada exitosamente"
    }), 201

@app.route('/api/registros', methods=['GET'])
def obtener_registros():
    # Obtenemos todos los registros para pintarlos en tu tabla web
    registros = []
    for reg in coleccion_altas.find().sort("fecha", -1):
        registros.append({
            "_id": str(reg['_id']),
            "servicio": reg['servicio'],
            "cuenta": reg['cuenta'],
            "fecha": reg['fecha'].strftime("%Y-%m-%d %H:%M:%S"),
            "estado": reg['estado']
        })
    return jsonify(registros), 200

@app.route('/api/validar-pin', methods=['POST'])
def validar_pin():
    data = request.json
    cuenta = data.get('cuenta')
    pin_ingresado = data.get('pin')

    # Buscamos al usuario en la BD
    usuario = coleccion_altas.find_one({"cuenta": cuenta})
    
    if not usuario:
        return jsonify({"valido": False, "mensaje": "Usuario no encontrado"}), 404

    # Usamos la llave que guardamos al inicio para comprobar el PIN
    totp = pyotp.TOTP(usuario['secreto'])
    es_valido = totp.verify(pin_ingresado)

    if es_valido:
        return jsonify({"valido": True, "mensaje": "Autenticación exitosa"}), 200
    else:
        return jsonify({"valido": False, "mensaje": "PIN incorrecto o expirado"}), 401

@app.route('/api/revocar/<id>', methods=['PUT'])
def revocar_registro(id):
    try:
        # Busco por ID y le cambio el estado a 'Revocado'
        coleccion_altas.update_one(
            {"_id": ObjectId(id)}, 
            {"$set": {"estado": "Revocado"}}
        )
        return jsonify({"mensaje": "Registro revocado exitosamente"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/eliminar/<id>', methods=['DELETE'])
def eliminar_registro(id):
    try:
        # Busco por ID y lo elimino de la colección
        coleccion_altas.delete_one({"_id": ObjectId(id)})
        return jsonify({"mensaje": "Registro eliminado exitosamente"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/activar-alta', methods=['POST'])
def activar_alta():
    data = request.json
    id_registro = data.get('id')
    pin_ingresado = data.get('pin')

    # 1. Busco el registro en mi base de datos usando el ID
    registro = coleccion_altas.find_one({"_id": ObjectId(id_registro)})
    
    if not registro:
        return jsonify({"valido": False, "mensaje": "Registro no encontrado"}), 404

    # 2. Recreo el objeto TOTP con la llave secreta guardada
    totp = pyotp.TOTP(registro['secreto'])
    
    # 3. Verifico si el PIN ingresado coincide con el tiempo actual
    if totp.verify(pin_ingresado):
        # Si es correcto, actualizo el estado en MongoDB a 'Activo'
        coleccion_altas.update_one(
            {"_id": ObjectId(id_registro)}, 
            {"$set": {"estado": "Activo"}}
        )
        return jsonify({"valido": True, "mensaje": "Autenticador activado exitosamente"}), 200
    else:
        return jsonify({"valido": False, "mensaje": "PIN incorrecto o expirado"}), 400
    
if __name__ == '__main__':
    app.run(debug=True, port=5000)