import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file
import secrets
import bcrypt
import pyotp
import gzip 

def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson
    
"""
function loadDatabaseSettings(pathjs):
    string = file_get_contents(pathjs);
    json_a = json_decode(string, true);
    return json_a;

"""
def getToken():
    return secrets.token_hex(16)

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    ####/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    # TODO checar si estan vacio los elementos del json
    if not R:
        return {"R":-1}
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            #ANTES: MD5 sin SALT (Bcrypt)
            #cursor.execute(
            #   'INSERT INTO Usuario VALUES (null, %s, %s, MD5(%s))',
            # (request.json["uname"], request.json["email"], request.json["password"])
            #)
            
            #DESPUES (Parche) Hashing seguro con bcrypt + salt (Bcrypt)
            hashed_pw = bcrypt.hashpw(
                request.json["password"].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            ### TOTP 
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=request.json["email"],
                issuer_name="InsecureWebAPI"
            )          
            #cursor.execute(
            #    'INSERT INTO Usuario VALUES (null, %s, %s, %s)',
            #    (request.json["uname"], request.json["email"], hashed_pw)
            #)
            
            #TOTP
            cursor.execute(
            'INSERT INTO Usuario (id, uname, email, password, totp_secret) VALUES (null, %s, %s, %s, %s)',
            (request.json["uname"], request.json["email"], hashed_pw, totp_secret)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e) 
        return {"R":-2}
    #return {"R":0,"D":R}
    #TOTP
    return {"R":0, "D":{"id": R, "totp_secret": totp_secret, "totp_uri": totp_uri}}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'uname' in request.json  and 'password' in request.json
    # TODO checar si estan vacio los elementos del json
    if not R:
        return {"R":-1}
    
    # TODO validar correo en json
    # TODO Control de error de la DB
    R = False
    try:
        with db.cursor() as cursor:
            # ANTES 
            #print(f'Select id from Usuario where uname = %s and password = md5(%s)')
            #cursor.execute('SELECT id FROM Usuario WHERE uname = %s AND password = MD5(%s)',(request.json["uname"], request.json["password"]))
            
            #DESPUES: (Parche) Obtener hash de BD y validar con bcrypt
            #cursor.execute(
            #    'SELECT id, password FROM Usuario WHERE uname = %s',
            #    (request.json["uname"],)
            #)
            
            #TOTP Autenticacion multifactor (2FA) validando codigo TOTP de 6 digitos
            cursor.execute(
                'SELECT id, password, totp_secret FROM Usuario WHERE uname = %s',
                (request.json["uname"],)
            )
            R = cursor.fetchall()
            if not R or not bcrypt.checkpw(request.json["password"].encode('utf-8'), R[0][1].encode('utf-8')):
                db.close()
                return {"R": -3}

            totp_secret = R[0][2]
            if totp_secret:
                codigo_totp = str(request.json.get("totp", "")).strip()
                if not codigo_totp or not pyotp.TOTP(totp_secret).verify(codigo_totp, valid_window=1):
                    db.close()
                    return {"R": -5}
            
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
    
    # ANTES 
    #if not R:
    #    db.close()
    #    return {"R":-3}
    
    # --- DESPUES (PARCHE) Valida existencia de usuario y verifica hash bcrypt) 
    #if not R or not bcrypt.checkpw(request.json["password"].encode('utf-8'), R[0][1].encode('utf-8')):
    #    db.close()
    #    return {"R": -3}
    
    T = getToken();
    #file_put_contents('/tmp/log','insert into AccesoToken values('.R[0].',"'.T.'",now())');
    with open("/tmp/log","a") as log:
        log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
        log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')
    
    
    try:
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM AccesoToken WHERE id_Usuario = %s',(R[0][0],));
            cursor.execute('INSERT INTO AccesoToken VALUES (%s, %s, now())', (R[0][0], T))
            db.commit()
            db.close()
            return {"R":0,"D":T}
    except Exception as e:
        print(e)
        db.close()
        return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
    #Directorio
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()
    
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
    # TODO checar si estan vacio los elementos del json
    if not R:
        return {"R":-1}
    
    dbcnf = loadDatabaseSettings('db.json');
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )

    # Validar si el usuario esta en la base de datos
    TKN = request.json['token'];
    
    R = False
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s',(TKN,));
            R = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
    
    
    id_Usuario = R[0][0];
    with open(f'tmp/{id_Usuario}',"wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))
    
    ############################
    ############################
    # Guardar info del archivo en la base de datos
    try:
        with db.cursor() as cursor:
            cursor.execute('INSERT INTO Imagen VALUES (null, %s, "img/", %s)',(request.json["name"], id_Usuario));
            cursor.execute('SELECT MAX(id) AS idImagen FROM Imagen WHERE id_Usuario = %s', (id_Usuario,))
            R = cursor.fetchall()
            idImagen = R[0][0];
            nueva_ruta = f"img/{idImagen}.{request.json['ext']}"
            cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s',(nueva_ruta, idImagen));
            db.commit()
            # Mover archivo a su nueva locacion
            shutil.move('tmp/'+str(id_Usuario),'img/'+str(idImagen)+'.'+str(request.json['ext']))
            return {"R":0,"D":idImagen}
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}
    
@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()

    if not request.json:
        return {"R": -1}

    R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
    if not R:
        return {"R": -1}

    # --- PARCHE A04: Validar extension permitida (evita subir .py/.php o Path Traversal) ---
    ext = str(request.json['ext']).lower().strip().replace('.', '')
    extensiones_validas = ['png', 'jpg', 'jpeg', 'gif']
    if ext not in extensiones_validas:
        return {"R": -4}

    # --- PARCHE A04: Validar Base64, descomprimir Gzip y limitar tamano (Anti Gzip Bomb) ---
    try:
        datos_comprimidos = base64.b64decode(request.json['data'].encode('utf-8'), validate=True)
    except Exception:
        return {"R": -5}

    tamano_max_comprimido = 2 * 1024 * 1024  # 2 MB comprimido
    tamano_max_real = 5 * 1024 * 1024        # 5 MB descomprimido

    if len(datos_comprimidos) == 0 or len(datos_comprimidos) > tamano_max_comprimido:
        return {"R": -6}

    try:
        if datos_comprimidos[:2] == b'\x1f\x8b':
            datos_imagen = gzip.decompress(datos_comprimidos)
        else:
            datos_imagen = datos_comprimidos
    except Exception:
        return {"R": -8}

    if len(datos_imagen) == 0 or len(datos_imagen) > tamano_max_real:
        return {"R": -6}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    # --- PARCHE A04 / A01: Verificar que el token exista en AccesoToken ---
    TKN = request.json['token']
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -7}

    id_Usuario = R[0][0]

    # --- PARCHE A01 / A04: Guardar archivo con nombre aleatorio impredecible ---
    nombre_aleatorio = secrets.token_hex(16)
    ruta_final = f"img/{nombre_aleatorio}.{ext}"
    ruta_temporal = f"tmp/{nombre_aleatorio}"

    with open(ruta_temporal, "wb") as imagen:
        imagen.write(datos_imagen)

    try:
        with db.cursor() as cursor:
            cursor.execute(
                'INSERT INTO Imagen VALUES (null, %s, %s, %s)',
                (request.json["name"], ruta_final, id_Usuario)
            )
            idImagen = cursor.lastrowid
            db.commit()
            shutil.move(ruta_temporal, ruta_final)
        db.close()
        return {"R": 0, "D": idImagen}
    except Exception as e:
        print(e)
        if Path(ruta_temporal).exists():
            Path(ruta_temporal).unlink()
        db.close()
        return {"R": -3}
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():
    if not request.json:
        return {"R": -1}

    R = 'token' in request.json and 'id' in request.json
    if not R:
        return {"R": -1}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    TKN = request.json['token']
    idImagen = request.json['id']

    # --- PARCHE A01: Verificar token valido y obtener dueno ---
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -4}

    id_Usuario = R[0][0]

    # --- PARCHE A01 (Anti-IDOR): Comprobar que la imagen pertenezca al usuario ---
    try:
        with db.cursor() as cursor:
            cursor.execute(
                'SELECT name, ruta FROM Imagen WHERE id = %s AND id_Usuario = %s',
                (idImagen, id_Usuario)
            )
            R = cursor.fetchall()
        db.close()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3}

    if not R:
        return {"R": -5}

    # --- Retornar la URL aleatoria de la imagen ---
    ruta_aleatoria = R[0][1]
    url_imagen = f"{request.urlparts.scheme}://{request.urlparts.netloc}/{ruta_aleatoria}"
    return {"R": 0, "D": {"name": R[0][0], "ruta": ruta_aleatoria, "url": url_imagen}}


@route('/img/<filename>')
def servir_imagen(filename):
    return static_file(filename, root=Path('img').resolve())


if __name__ == '__main__':
    run(host='localhost', port=8080, debug=False)
