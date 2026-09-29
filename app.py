from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import mysql.connector
import os
import re
import uuid
import random
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)


@app.context_processor
def inyectar_contador_carrito():
    """Pone el número de productos distintos en el carrito a disposición de cualquier template."""

    id_usuario = session.get('id_usuario')
    num_productos, num_unidades = contar_carrito(id_usuario)

    return {
        'carrito_num_productos': num_productos,
        'carrito_num_unidades': num_unidades
    }

app.secret_key = "animalum123"
# =====================================
# CONFIGURACIÓN BASE DE DATOS
# =====================================

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'negocio'),
    'password': os.getenv('DB_PASSWORD', 'minegoapp'),
    'database': os.getenv('DB_NAME', 'registro')
}

# =====================================
# CONFIGURACIÓN DE CORREO (RECUPERAR CONTRASEÑA)
# =====================================
# Para que el envío de correos funcione de verdad, reemplaza 'usuario' y
# 'password' con una cuenta de Gmail y una "contraseña de aplicación"
# (no la contraseña normal de la cuenta).
# Guía: https://support.google.com/mail/answer/185833
#
# Mientras no configures estos datos, el sistema seguirá funcionando:
# el enlace de recuperación se imprimirá en la consola donde corre Flask
# para que puedas probarlo sin necesidad de un correo real.

MAIL_CONFIG = {
    'servidor': 'smtp.gmail.com',
    'puerto': 587,
    'usuario': os.getenv('MAIL_USER', 'tu_correo@gmail.com'),
    'password': os.getenv('MAIL_PASSWORD', 'tu_contraseña_de_aplicacion'),
    'remitente': os.getenv('MAIL_FROM', 'Animalum <tu_correo@gmail.com>'),
    'admin': os.getenv('ADMIN_EMAIL', os.getenv('MAIL_USER', 'tu_correo@gmail.com'))
}

# Minutos de validez del enlace de recuperación de contraseña
RESET_TOKEN_MINUTOS = 30

# =====================================
# CONFIGURACIÓN DE IMÁGENES DE PRODUCTOS
# =====================================

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'img')
EXTENSIONES_PERMITIDAS = {'png', 'jpg', 'jpeg', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB máximo por imagen


def extension_permitida(nombre_archivo):
    return (
        '.' in nombre_archivo
        and nombre_archivo.rsplit('.', 1)[1].lower() in EXTENSIONES_PERMITIDAS
    )


def guardar_imagen_producto(archivo):
    """Guarda la imagen subida en static/img con un nombre único y devuelve el nombre de archivo."""

    nombre_seguro = secure_filename(archivo.filename)
    extension = nombre_seguro.rsplit('.', 1)[1].lower()
    nombre_final = f"{uuid.uuid4().hex}.{extension}"

    ruta_destino = os.path.join(app.config['UPLOAD_FOLDER'], nombre_final)
    archivo.save(ruta_destino)

    return nombre_final


# =====================================
# CONEXIÓN MYSQL
# =====================================

def conectar_bd():
    return mysql.connector.connect(**db_config)


# =====================================
# DECORADORES DE ACCESO (ROLES)
# =====================================

def login_required(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if session.get('id_usuario') is None:
            flash("Debes iniciar sesión para acceder a esta página.", "error")
            return redirect(url_for('login'))
        return vista(*args, **kwargs)
    return envoltura


def admin_required(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if session.get('id_usuario') is None:
            flash("Debes iniciar sesión para acceder a esta página.", "error")
            return redirect(url_for('login'))
        if session.get('rol') != 'admin':
            flash("No tienes permisos de administrador para acceder a esta página.", "error")
            return redirect(url_for('inicio'))
        return vista(*args, **kwargs)
    return envoltura


# =====================================
# VALIDAR CORREO
# =====================================
def correo_existe(correo):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT id_usuario FROM usuarios WHERE correo=%s",
        (correo,)
    )

    resultado = cursor.fetchone()

    cursor.close()
    conexion.close()

    return resultado is not None



def correo_ocupado(correo, id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT id_usuario
        FROM usuarios
        WHERE correo = %s
        AND id_usuario <> %s
    """, (correo, id_usuario))

    existe = cursor.fetchone()

    cursor.close()
    conexion.close()

    return existe is not None

# =====================================
# RECUPERACIÓN DE CONTRASEÑA
# =====================================

def generar_token_reset(correo):
    """Si el correo existe, genera un token de recuperación y lo guarda
    en la base de datos junto con su fecha de expiración.
    Devuelve el token, o None si el correo no está registrado."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT id_usuario FROM usuarios WHERE correo = %s",
        (correo,)
    )

    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        conexion.close()
        return None

    token = secrets.token_urlsafe(32)
    expira = datetime.now() + timedelta(minutes=RESET_TOKEN_MINUTOS)

    cursor.execute(
        """
        UPDATE usuarios
        SET reset_token = %s, reset_token_expira = %s
        WHERE correo = %s
        """,
        (token, expira, correo)
    )

    conexion.commit()

    cursor.close()
    conexion.close()

    return token


def obtener_usuario_por_token(token):
    """Devuelve el id_usuario y correo asociados a un token de recuperación
    válido (que exista y no haya expirado). Si no es válido, devuelve None."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        """
        SELECT id_usuario, correo, reset_token_expira
        FROM usuarios
        WHERE reset_token = %s
        """,
        (token,)
    )

    resultado = cursor.fetchone()

    cursor.close()
    conexion.close()

    if not resultado:
        return None

    id_usuario, correo, expira = resultado

    if expira is None or datetime.now() > expira:
        return None

    return {'id_usuario': id_usuario, 'correo': correo}


def actualizar_password_usuario(id_usuario, nueva_password):
    """Actualiza la contraseña del usuario y elimina el token de
    recuperación para que no pueda volver a usarse."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    password_hash = generate_password_hash(nueva_password)

    cursor.execute(
        """
        UPDATE usuarios
        SET password = %s, reset_token = NULL, reset_token_expira = NULL
        WHERE id_usuario = %s
        """,
        (password_hash, id_usuario)
    )

    conexion.commit()

    cursor.close()
    conexion.close()


def enviar_correo_recuperacion(correo, token):
    """Envía el correo con el enlace de recuperación de contraseña.
    Si el envío falla (por ejemplo, porque MAIL_CONFIG no se ha
    configurado todavía), el enlace se imprime en la consola para
    que el enlace se pueda seguir probando en desarrollo."""

    enlace = url_for('restablecer_password', token=token, _external=True)

    cuerpo = (
        "Hola,\n\n"
        "Recibimos una solicitud para restablecer la contraseña de tu cuenta en Animalum.\n"
        f"Este enlace es válido por {RESET_TOKEN_MINUTOS} minutos:\n\n"
        f"{enlace}\n\n"
        "Si tú no solicitaste este cambio, puedes ignorar este correo."
    )

    mensaje = MIMEText(cuerpo, _charset='utf-8')
    mensaje['Subject'] = 'Recuperación de contraseña - Animalum'
    mensaje['From'] = MAIL_CONFIG['remitente']
    mensaje['To'] = correo

    try:
        with smtplib.SMTP(MAIL_CONFIG['servidor'], MAIL_CONFIG['puerto']) as servidor:
            servidor.starttls()
            servidor.login(MAIL_CONFIG['usuario'], MAIL_CONFIG['password'])
            servidor.sendmail(MAIL_CONFIG['usuario'], [correo], mensaje.as_string())
        return True
    except Exception as error:
        print("=====================================================")
        print("No se pudo enviar el correo de recuperación (revisa MAIL_CONFIG).")
        print(f"Error: {error}")
        print(f"Enlace de recuperación para {correo}: {enlace}")
        print("=====================================================")
        return False


def enviar_correo_contacto(nombre, correo, telefono, asunto, mensaje):
    """Envía el mensaje recibido desde el formulario de contacto al administrador."""

    destinatario = MAIL_CONFIG.get('admin') or MAIL_CONFIG.get('usuario') or 'tu_correo@gmail.com'
    telefono_texto = telefono or 'No registrado'
    cuerpo = (
        f"Nuevo mensaje de contacto recibido en Animalum\n\n"
        f"Nombre: {nombre}\n"
        f"Correo: {correo}\n"
        f"Teléfono: {telefono_texto}\n"
        f"Asunto: {asunto}\n\n"
        f"Mensaje:\n{mensaje}"
    )
    email = MIMEText(cuerpo, _charset='utf-8')
    email['Subject'] = f'Nuevo contacto - {asunto}'
    email['From'] = MAIL_CONFIG['remitente']
    email['To'] = destinatario

    try:
        with smtplib.SMTP(MAIL_CONFIG['servidor'], MAIL_CONFIG['puerto']) as servidor:
            servidor.starttls()
            servidor.login(MAIL_CONFIG['usuario'], MAIL_CONFIG['password'])
            servidor.sendmail(MAIL_CONFIG['usuario'], [destinatario], email.as_string())
        print(f"Correo de contacto enviado al administrador: {destinatario}")
        return True
    except Exception as error:
        print("=====================================================")
        print("No se pudo enviar el correo del formulario de contacto (revisa MAIL_CONFIG).")
        print(f"Error: {error}")
        print("Detalle del mensaje pendiente:")
        print(cuerpo)
        print("=====================================================")
        return False

# =====================================
# INSERTAR USUARIO
# =====================================

def insertar_usuario(nombre, apellido, correo, direccion, password, rol='cliente'):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    password_hash = generate_password_hash(password)

    sql = """
    INSERT INTO usuarios
    (nombre, apellido, correo, direccion, password, rol)
    VALUES (%s, %s, %s, %s, %s, %s)
    """

    cursor.execute(
        sql,
        (
            nombre,
            apellido,
            correo,
            direccion,
            password_hash,
            rol
        )
    )

    conexion.commit()

    id_usuario = cursor.lastrowid

    cursor.close()
    conexion.close()

    return id_usuario
# =====================================
# INSERTAR MASCOTA
# =====================================

def insertar_mascota(id_usuario, nombre_mascota, tipo, raza, edad):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO mascotas
    (
        id_usuario,
        nombre_mascota,
        tipo,
        raza,
        edad
    )
    VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(
        sql,
        (
            id_usuario,
            nombre_mascota,
            tipo,
            raza,
            edad
        )
    )

    conexion.commit()

    cursor.close()
    conexion.close()


def registrar_usuario_con_mascotas(nombre, apellido, correo, direccion, password, mascotas):
    """Crea el cliente y todas sus mascotas en una sola transacción."""
    conexion = conectar_bd()
    cursor = conexion.cursor()

    try:
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO usuarios
            (nombre, apellido, correo, direccion, password, rol)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (nombre, apellido, correo, direccion, password_hash, 'cliente')
        )

        id_usuario = cursor.lastrowid
        cursor.executemany(
            """
            INSERT INTO mascotas
            (id_usuario, nombre_mascota, tipo, raza, edad)
            VALUES (%s, %s, %s, %s, %s)
            """,
            [
                (
                    id_usuario,
                    mascota['nombre'],
                    mascota['tipo'],
                    mascota['raza'],
                    mascota['edad']
                )
                for mascota in mascotas
            ]
        )

        conexion.commit()
        return id_usuario
    except Exception:
        conexion.rollback()
        raise
    finally:
        cursor.close()
        conexion.close()

# =====================================
# INSERTAR CONTACTO
# =====================================
# =====================================
# INSERTAR ENVIO
# =====================================

def insertar_envio(id_usuario, nombre_receptor, telefono, direccion, ciudad, departamento, codigo_postal, metodo_pago, observaciones):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO envios
    (
        id_usuario,
        nombre_receptor,
        telefono,
        direccion,
        ciudad,
        departamento,
        codigo_postal,
        metodo_pago,
        observaciones
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    cursor.execute(
        sql,
        (
            id_usuario,
            nombre_receptor,
            telefono,
            direccion,
            ciudad,
            departamento,
            codigo_postal,
            metodo_pago,
            observaciones
        )
    )

    conexion.commit()

    id_envio = cursor.lastrowid

    cursor.close()
    conexion.close()

    return id_envio


def insertar_factura(id_usuario, id_envio, total, metodo_pago, observaciones):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO facturas
    (
        id_usuario,
        id_envio,
        total,
        metodo_pago,
        observaciones
    )
    VALUES (%s,%s,%s,%s,%s)
    """

    cursor.execute(
        sql,
        (
            id_usuario,
            id_envio,
            total,
            metodo_pago,
            observaciones
        )
    )

    conexion.commit()

    id_factura = cursor.lastrowid

    cursor.close()
    conexion.close()

    return id_factura


def insertar_items_factura(id_factura, carrito):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO factura_items
    (
        id_factura,
        id_producto,
        nombre_producto,
        precio,
        cantidad,
        subtotal
    )
    VALUES (%s,%s,%s,%s,%s,%s)
    """

    for item in carrito:
        cursor.execute(
            sql,
            (
                id_factura,
                item[1],
                item[2],
                item[3],
                item[5],
                item[6]
            )
        )

    conexion.commit()

    cursor.close()
    conexion.close()


def vaciar_carrito_usuario(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "DELETE FROM carrito WHERE id_usuario=%s",
        (id_usuario,)
    )

    conexion.commit()

    cursor.close()
    conexion.close()


def obtener_factura(id_factura, id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            f.id_factura,
            f.total,
            f.fecha,
            f.estado,
            f.metodo_pago,
            f.observaciones,
            e.nombre_receptor,
            e.telefono,
            e.direccion,
            e.ciudad,
            e.departamento,
            e.codigo_postal,
            u.nombre,
            u.apellido,
            u.correo
        FROM facturas f
        INNER JOIN envios e ON f.id_envio = e.id_envio
        INNER JOIN usuarios u ON f.id_usuario = u.id_usuario
        WHERE f.id_factura = %s
        AND f.id_usuario = %s
    """, (id_factura, id_usuario))

    factura = cursor.fetchone()

    cursor.close()
    conexion.close()

    return factura


def obtener_items_factura(id_factura):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            nombre_producto,
            precio,
            cantidad,
            subtotal
        FROM factura_items
        WHERE id_factura = %s
    """, (id_factura,))

    items = cursor.fetchall()

    cursor.close()
    conexion.close()

    return items


def obtener_facturas_usuario(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            f.id_factura,
            f.fecha,
            f.total,
            f.estado,
            f.metodo_pago,
            e.direccion
        FROM facturas f
        INNER JOIN envios e ON f.id_envio = e.id_envio
        WHERE f.id_usuario = %s
        ORDER BY f.fecha DESC
    """, (id_usuario,))

    facturas = cursor.fetchall()

    cursor.close()
    conexion.close()

    return facturas


def insertar_contacto(nombre, correo, telefono, asunto, mensaje):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO contactos
    (
        nombre,
        correo,
        telefono,
        asunto,
        mensaje
    )
    VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(
        sql,
        (
            nombre,
            correo,
            telefono,
            asunto,
            mensaje
        )
    )

    conexion.commit()

    cursor.close()
    conexion.close()

def obtener_contactos():

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            id_contacto,
            nombre,
            correo,
            telefono,
            asunto,
            mensaje,
            fecha_envio
        FROM contactos
        ORDER BY fecha_envio DESC
    """)

    contactos = cursor.fetchall()

    cursor.close()
    conexion.close()

    return contactos


def obtener_usuarios():

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            id_usuario,
            nombre,
            apellido,
            correo,
            direccion,
            rol
        FROM usuarios
        ORDER BY id_usuario
    """)

    usuarios = cursor.fetchall()

    cursor.close()
    conexion.close()

    return usuarios


def alternar_rol_usuario(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT rol FROM usuarios WHERE id_usuario=%s",
        (id_usuario,)
    )

    resultado = cursor.fetchone()

    if resultado is None:
        cursor.close()
        conexion.close()
        return

    nuevo_rol = 'cliente' if resultado[0] == 'admin' else 'admin'

    cursor.execute(
        "UPDATE usuarios SET rol=%s WHERE id_usuario=%s",
        (nuevo_rol, id_usuario)
    )

    conexion.commit()

    cursor.close()
    conexion.close()

# =====================================
# OBTENER UN PRODUCTO
# =====================================

def obtener_producto(id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            id_producto,
            nombre,
            descripcion,
            precio,
            imagen,
            categoria,
            stock
        FROM productos
        WHERE id_producto = %s
    """, (id_producto,))

    producto = cursor.fetchone()

    cursor.close()
    conexion.close()

    return producto


# =====================================
# BUSCADOR INTELIGENTE: SINÓNIMOS DE CATEGORÍAS
# =====================================
# Permite que términos comunes (ej. "comida") encuentren productos
# de la categoría relacionada (ej. "Alimentos"), aunque el texto no
# coincida literalmente con el nombre de la categoría en la BD.

CATEGORIAS_SINONIMOS = {
    'Alimentos': ['alimento', 'alimentos', 'comida', 'comidas', 'comer',
                  'pienso', 'concentrado', 'croquetas', 'food'],
    'Juguetes': ['juguete', 'juguetes', 'jugar', 'juego', 'pelota', 'toy', 'toys'],
    'Accesorios': ['accesorio', 'accesorios', 'correa', 'collar', 'collares',
                   'ropa', 'arnes', 'arnés'],
    'Higiene': ['higiene', 'limpieza', 'baño', 'shampoo', 'champu', 'champú', 'aseo'],
    'Salud': ['salud', 'medicina', 'medicamento', 'vitaminas', 'veterinario',
              'veterinaria', 'antipulgas'],
    'VIP': ['vip', 'premium', 'exclusivo', 'exclusivos'],
}


def resolver_categorias_por_sinonimo(termino):
    """Dado un término de búsqueda, devuelve la(s) categoría(s) reales de
    la BD relacionadas por sinónimo (ej. 'comida' -> ['Alimentos'])."""

    termino_normalizado = termino.strip().lower()

    if not termino_normalizado:
        return []

    categorias_encontradas = []

    for categoria, sinonimos in CATEGORIAS_SINONIMOS.items():

        if termino_normalizado in categoria.lower():
            categorias_encontradas.append(categoria)
            continue

        for sinonimo in sinonimos:
            if termino_normalizado in sinonimo or sinonimo in termino_normalizado:
                categorias_encontradas.append(categoria)
                break

    return categorias_encontradas


# Orden en el que se muestran las secciones de categorías en /productos
ORDEN_CATEGORIAS = ['Alimentos', 'Juguetes', 'Accesorios', 'Higiene', 'Salud']


def agrupar_productos_por_categoria(productos):
    """Agrupa una lista de productos (tuplas de obtener_productos) por su
    categoría, devolviendo una lista de tuplas (categoria, [productos])
    en un orden fijo y amigable. Excluye la categoría 'VIP', que ya se
    muestra en su propia sección destacada."""

    grupos = {}

    for producto in productos:

        categoria = producto[5] or 'Otros'

        if categoria == 'VIP':
            continue

        grupos.setdefault(categoria, []).append(producto)

    categorias_ordenadas = [c for c in ORDEN_CATEGORIAS if c in grupos]
    categorias_restantes = sorted(c for c in grupos if c not in ORDEN_CATEGORIAS)

    return [(c, grupos[c]) for c in categorias_ordenadas + categorias_restantes]


# =====================================
# OBTENER TODOS LOS PRODUCTOS
# =====================================

def obtener_productos(busqueda=None):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    if busqueda:

        termino = f"%{busqueda}%"
        categorias_relacionadas = resolver_categorias_por_sinonimo(busqueda)

        condiciones = ["nombre LIKE %s", "descripcion LIKE %s", "categoria LIKE %s"]
        parametros = [termino, termino, termino]

        if categorias_relacionadas:
            marcadores = ','.join(['%s'] * len(categorias_relacionadas))
            condiciones.append(f"categoria IN ({marcadores})")
            parametros.extend(categorias_relacionadas)

        sql = f"""
            SELECT
                id_producto,
                nombre,
                descripcion,
                precio,
                imagen,
                categoria,
                stock
            FROM productos
            WHERE ({' OR '.join(condiciones)})
            AND categoria <> 'VIP'
            ORDER BY nombre
        """

        cursor.execute(sql, tuple(parametros))

    else:

        cursor.execute("""
            SELECT
                id_producto,
                nombre,
                descripcion,
                precio,
                imagen,
                categoria,
                stock
            FROM productos
            WHERE categoria <> 'VIP'
            ORDER BY nombre
        """)

    productos = cursor.fetchall()

    cursor.close()
    conexion.close()

    return productos


def buscar_productos_rapido(termino, limite=8):
    """Búsqueda ligera usada por el buscador inteligente del navbar.
    También reconoce sinónimos de categorías (ej. 'comida' -> Alimentos)."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    patron = f"%{termino}%"
    categorias_relacionadas = resolver_categorias_por_sinonimo(termino)

    condiciones = [
        "nombre LIKE %s",
        "descripcion LIKE %s",
        "categoria LIKE %s"
    ]
    parametros = [patron, patron, patron]

    if categorias_relacionadas:
        marcadores = ','.join(['%s'] * len(categorias_relacionadas))
        condiciones.append(f"categoria IN ({marcadores})")
        parametros.extend(categorias_relacionadas)

    sql = f"""
        SELECT id_producto, nombre, precio, imagen, categoria
        FROM productos
        WHERE ({' OR '.join(condiciones)})
        AND categoria <> 'VIP'
        ORDER BY
            CASE WHEN nombre LIKE %s THEN 0 ELSE 1 END,
            nombre
        LIMIT %s
    """

    parametros.append(patron)
    parametros.append(limite)

    cursor.execute(sql, tuple(parametros))

    resultados = cursor.fetchall()

    cursor.close()
    conexion.close()

    return resultados


def obtener_productos_vip():

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            id_producto,
            nombre,
            descripcion,
            precio,
            imagen,
            categoria,
            stock
        FROM productos
        WHERE categoria = 'VIP'
        ORDER BY nombre
    """)

    productos = cursor.fetchall()

    cursor.close()
    conexion.close()

    return productos


# =====================================
# SUSCRIPCIÓN VIP
# =====================================

def es_usuario_vip(id_usuario):
    """True solo si el usuario tiene la suscripción VIP activa.
    Se valida siempre contra la base de datos (nunca confiando en
    la sesión ni en el frontend), para que la Zona VIP quede
    protegida también del lado del servidor."""

    if id_usuario is None:
        return False

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT vip_activo FROM usuarios WHERE id_usuario=%s",
        (id_usuario,)
    )

    fila = cursor.fetchone()

    cursor.close()
    conexion.close()

    return bool(fila and fila[0])


def activar_suscripcion_vip(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE usuarios
        SET vip_activo = 1, vip_desde = NOW()
        WHERE id_usuario = %s
    """, (id_usuario,))

    conexion.commit()

    cursor.close()
    conexion.close()


def cancelar_suscripcion_vip(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE usuarios
        SET vip_activo = 0
        WHERE id_usuario = %s
    """, (id_usuario,))

    conexion.commit()

    cursor.close()
    conexion.close()


# =====================================
# CRUD DE PRODUCTOS (ADMINISTRADOR)
# =====================================

def insertar_producto(nombre, descripcion, precio, imagen, categoria, stock):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    INSERT INTO productos
    (nombre, descripcion, precio, imagen, categoria, stock)
    VALUES (%s, %s, %s, %s, %s, %s)
    """

    cursor.execute(sql, (nombre, descripcion, precio, imagen, categoria, stock))

    conexion.commit()

    id_producto = cursor.lastrowid

    cursor.close()
    conexion.close()

    return id_producto


def actualizar_producto(id_producto, nombre, descripcion, precio, categoria, stock, imagen=None):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    if imagen:
        cursor.execute("""
            UPDATE productos
            SET nombre=%s, descripcion=%s, precio=%s, categoria=%s, stock=%s, imagen=%s
            WHERE id_producto=%s
        """, (nombre, descripcion, precio, categoria, stock, imagen, id_producto))
    else:
        cursor.execute("""
            UPDATE productos
            SET nombre=%s, descripcion=%s, precio=%s, categoria=%s, stock=%s
            WHERE id_producto=%s
        """, (nombre, descripcion, precio, categoria, stock, id_producto))

    conexion.commit()

    cursor.close()
    conexion.close()


def eliminar_producto(id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute(
        "DELETE FROM productos WHERE id_producto=%s",
        (id_producto,)
    )

    conexion.commit()

    cursor.close()
    conexion.close()

# =====================================
# OBTENER CARRITO
# =====================================

def obtener_carrito(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            carrito.id_carrito,
            productos.id_producto,
            productos.nombre,
            productos.precio,
            productos.imagen,
            carrito.cantidad,
            (productos.precio * carrito.cantidad) AS subtotal
        FROM carrito
        INNER JOIN productos
        ON carrito.id_producto = productos.id_producto
        WHERE carrito.id_usuario = %s
    """, (id_usuario,))

    carrito = cursor.fetchall()

    cursor.close()
    conexion.close()

    return carrito

# =====================================
# CONTAR ITEMS DEL CARRITO
# =====================================

def contar_carrito(id_usuario):
    """Devuelve (numero_productos_distintos, unidades_totales) del carrito de un usuario."""

    if id_usuario is None:
        return (0, 0)

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT COUNT(*), COALESCE(SUM(cantidad), 0)
        FROM carrito
        WHERE id_usuario = %s
    """, (id_usuario,))

    fila = cursor.fetchone()

    cursor.close()
    conexion.close()

    if not fila:
        return (0, 0)

    return (fila[0], int(fila[1]))


# =====================================
# TOTAL DEL CARRITO
# =====================================

def calcular_total(carrito):

    total = 0

    for producto in carrito:
        total += producto[6]

    return total
# =====================================
# AGREGAR AL CARRITO
# =====================================

def agregar_carrito(id_usuario, id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT c.cantidad, p.stock
        FROM productos p
        LEFT JOIN carrito c
            ON c.id_producto = p.id_producto
            AND c.id_usuario = %s
        WHERE p.id_producto = %s
    """,(id_usuario,id_producto))

    producto = cursor.fetchone()

    if producto is None:
        cursor.close()
        conexion.close()
        return False, 'producto_no_encontrado'

    cantidad_actual = producto[0] or 0
    stock = producto[1] or 0

    if stock <= cantidad_actual:
        cursor.close()
        conexion.close()
        return False, 'sin_stock'

    if cantidad_actual:

        cursor.execute("""
            UPDATE carrito
            SET cantidad = cantidad + 1
            WHERE id_usuario=%s
            AND id_producto=%s
        """,(id_usuario,id_producto))

    else:

        cursor.execute("""
            INSERT INTO carrito
            (id_usuario,id_producto,cantidad)
            VALUES(%s,%s,1)
        """,(id_usuario,id_producto))

    conexion.commit()

    cursor.close()
    conexion.close()
    return True, None


def actualizar_cantidad_carrito(id_usuario, id_carrito, cantidad):
    """Actualiza una línea del carrito verificando usuario y stock."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT p.stock
        FROM carrito c
        INNER JOIN productos p ON p.id_producto = c.id_producto
        WHERE c.id_carrito = %s AND c.id_usuario = %s
    """, (id_carrito, id_usuario))

    fila = cursor.fetchone()

    if fila is None:
        cursor.close()
        conexion.close()
        return False, 'producto_no_encontrado'

    stock = int(fila[0] or 0)

    if cantidad <= 0:
        cursor.execute(
            "DELETE FROM carrito WHERE id_carrito=%s AND id_usuario=%s",
            (id_carrito, id_usuario)
        )
    else:
        if stock <= 0:
            cursor.execute(
                "DELETE FROM carrito WHERE id_carrito=%s AND id_usuario=%s",
                (id_carrito, id_usuario)
            )
        else:
            cantidad = min(cantidad, stock)
            cursor.execute("""
                UPDATE carrito
                SET cantidad = %s
                WHERE id_carrito = %s AND id_usuario = %s
            """, (cantidad, id_carrito, id_usuario))

    conexion.commit()
    cursor.close()
    conexion.close()
    return True, None


# =====================================
# RULETA DE DESCUENTOS
# =====================================

# Compras necesarias para reactivar la ruleta después de usar un descuento
RULETA_COMPRAS_NECESARIAS = 15

# Premios posibles (porcentaje de descuento) y su peso relativo de probabilidad
# (números más bajos son más probables que los más altos)
RULETA_PREMIOS = [5, 10, 15, 20, 30, 50]
RULETA_PESOS   = [30, 25, 20, 15, 7, 3]


def obtener_estado_ruleta(id_usuario):
    """Devuelve el estado actual de la ruleta para un usuario."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT ruleta_disponible, ruleta_descuento, ruleta_compras
        FROM usuarios
        WHERE id_usuario = %s
    """, (id_usuario,))

    fila = cursor.fetchone()

    cursor.close()
    conexion.close()

    if fila is None:
        return None

    return {
        'disponible': bool(fila[0]),
        'descuento_activo': fila[1],
        'compras': fila[2],
        'faltan_compras': max(RULETA_COMPRAS_NECESARIAS - fila[2], 0)
    }


def girar_ruleta(id_usuario):
    """Gira la ruleta para el usuario si tiene un giro disponible.

    Devuelve el porcentaje ganado, o None si no puede girar en este momento.
    """

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT ruleta_disponible, ruleta_descuento
        FROM usuarios
        WHERE id_usuario = %s
        FOR UPDATE
    """, (id_usuario,))

    fila = cursor.fetchone()

    if not fila or not fila[0] or fila[1] is not None:
        # No tiene giro disponible, o ya tiene un descuento pendiente de usar
        cursor.close()
        conexion.close()
        return None

    premio = random.choices(RULETA_PREMIOS, weights=RULETA_PESOS, k=1)[0]

    cursor.execute("""
        UPDATE usuarios
        SET ruleta_disponible = 0,
            ruleta_descuento = %s
        WHERE id_usuario = %s
    """, (premio, id_usuario))

    conexion.commit()

    cursor.close()
    conexion.close()

    return premio


def aplicar_descuento_ruleta(id_usuario, total):
    """Si el usuario tiene un descuento de ruleta pendiente, lo aplica al total
    de la compra actual y lo marca como usado (funciona una única vez).

    Devuelve una tupla (total_final, porcentaje_aplicado).
    """

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT ruleta_descuento
        FROM usuarios
        WHERE id_usuario = %s
        FOR UPDATE
    """, (id_usuario,))

    fila = cursor.fetchone()

    if not fila or fila[0] is None:
        cursor.close()
        conexion.close()
        return total, None

    porcentaje = fila[0]

    cursor.execute("""
        UPDATE usuarios
        SET ruleta_descuento = NULL
        WHERE id_usuario = %s
    """, (id_usuario,))

    conexion.commit()

    cursor.close()
    conexion.close()

    total_final = round(float(total) * (1 - (porcentaje / 100)), 2)

    return total_final, porcentaje


def registrar_compra_ruleta(id_usuario):
    """Cuenta una compra hacia la reactivación de la ruleta.

    Solo suma si la ruleta ya fue usada (no está disponible). Al llegar a
    las compras necesarias, reactiva la ruleta y reinicia el contador.
    """

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT ruleta_disponible, ruleta_compras
        FROM usuarios
        WHERE id_usuario = %s
        FOR UPDATE
    """, (id_usuario,))

    fila = cursor.fetchone()

    if not fila or fila[0]:
        # La ruleta ya está disponible (no hay nada que contar todavía)
        cursor.close()
        conexion.close()
        return

    nuevas_compras = fila[1] + 1

    if nuevas_compras >= RULETA_COMPRAS_NECESARIAS:

        cursor.execute("""
            UPDATE usuarios
            SET ruleta_disponible = 1,
                ruleta_compras = 0,
                ruleta_descuento = NULL
            WHERE id_usuario = %s
        """, (id_usuario,))

    else:

        cursor.execute("""
            UPDATE usuarios
            SET ruleta_compras = %s
            WHERE id_usuario = %s
        """, (nuevas_compras, id_usuario))

    conexion.commit()

    cursor.close()
    conexion.close()


# =====================================
# AETHERION — MASCOTA VIRTUAL Y CUPONES
# =====================================
# Aetherion es la mascota mística de gamificación de Animalum: el usuario
# la alimenta, juega con ella y la viste desde la página /aetherion. Todo
# su progreso (especie, hambre/felicidad/energía, racha de cuidado diario,
# ropa puesta y cupones de descuento desbloqueados) se guarda en la base
# de datos asociado al usuario que inició sesión, para que persista entre
# dispositivos y no dependa del navegador.

AETHERION_ESPECIES = {'zorro', 'gato', 'conejo', 'dragon'}
AETHERION_ROPA_POR_SLOT = {
    'hat': {'gorro'},
    'neck': {'bufanda'},
    'eyewear': {'gafas'}
}

# Porcentaje de descuento que otorga cada hito de racha (autoridad del
# servidor: aunque el widget calcula esto igual en el navegador, el
# descuento real que se aplica en el checkout siempre sale de aquí).
AETHERION_HITOS_DESCUENTO = {3: 5, 7: 10, 14: 15, 30: 20}


def _aetherion_clamp(valor, minimo=0, maximo=100, por_defecto=80):
    """Convierte 'valor' a un entero dentro de [minimo, maximo]."""
    try:
        valor = int(round(float(valor)))
    except (TypeError, ValueError):
        return por_defecto
    return max(minimo, min(maximo, valor))


def _aetherion_fecha_valida(valor):
    """Devuelve la fecha en formato YYYY-MM-DD si es válida, o None."""
    if not valor or not isinstance(valor, str):
        return None
    try:
        return datetime.strptime(valor, "%Y-%m-%d").date().isoformat()
    except ValueError:
        return None


def obtener_estado_aetherion(id_usuario):
    """Devuelve el estado guardado de la mascota Aetherion de un usuario
    (con valores por defecto si todavía no tiene una)."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT nombre, especie, xp, hambre, felicidad, energia, racha,
               ultima_atencion, outfit_hat, outfit_neck, outfit_eyewear,
               petting_fecha, petting_cantidad
        FROM aetherion_mascota
        WHERE id_usuario = %s
    """, (id_usuario,))

    fila = cursor.fetchone()

    cursor.execute("""
        SELECT hito, codigo
        FROM aetherion_cupones
        WHERE id_usuario = %s
    """, (id_usuario,))

    claimed = {str(hito): codigo for hito, codigo in cursor.fetchall()}

    cursor.close()
    conexion.close()

    if fila is None:
        return {
            'name': 'Luna',
            'species': 'zorro',
            'xp': 0,
            'hunger': 80,
            'happiness': 80,
            'energy': 80,
            'streak': 0,
            'lastCareDate': None,
            'claimed': claimed,
            'petting': {'date': None, 'count': 0},
            'outfit': {'hat': None, 'neck': None, 'eyewear': None}
        }

    (nombre, especie, xp, hambre, felicidad, energia, racha,
     ultima_atencion, outfit_hat, outfit_neck, outfit_eyewear,
     petting_fecha, petting_cantidad) = fila

    return {
        'name': nombre,
        'species': especie,
        'xp': xp,
        'hunger': hambre,
        'happiness': felicidad,
        'energy': energia,
        'streak': racha,
        'lastCareDate': ultima_atencion.isoformat() if ultima_atencion else None,
        'claimed': claimed,
        'petting': {
            'date': petting_fecha.isoformat() if petting_fecha else None,
            'count': petting_cantidad
        },
        'outfit': {'hat': outfit_hat, 'neck': outfit_neck, 'eyewear': outfit_eyewear}
    }


def guardar_estado_aetherion(id_usuario, datos):
    """Guarda (crea o actualiza) el estado de la mascota Aetherion de un
    usuario a partir del JSON enviado por el widget, validando y acotando
    cada valor antes de escribirlo en la base de datos."""

    if not isinstance(datos, dict):
        return False

    nombre = str(datos.get('name') or 'Luna').strip()[:18] or 'Luna'

    especie = datos.get('species')
    if especie not in AETHERION_ESPECIES:
        especie = 'zorro'

    try:
        xp = max(0, int(datos.get('xp', 0) or 0))
    except (TypeError, ValueError):
        xp = 0

    hambre = _aetherion_clamp(datos.get('hunger', 80))
    felicidad = _aetherion_clamp(datos.get('happiness', 80))
    energia = _aetherion_clamp(datos.get('energy', 80))

    try:
        racha = max(0, min(400, int(datos.get('streak', 0) or 0)))
    except (TypeError, ValueError):
        racha = 0

    ultima_atencion = _aetherion_fecha_valida(datos.get('lastCareDate'))

    outfit = datos.get('outfit') or {}
    outfit_hat = outfit.get('hat') if outfit.get('hat') in AETHERION_ROPA_POR_SLOT['hat'] else None
    outfit_neck = outfit.get('neck') if outfit.get('neck') in AETHERION_ROPA_POR_SLOT['neck'] else None
    outfit_eyewear = outfit.get('eyewear') if outfit.get('eyewear') in AETHERION_ROPA_POR_SLOT['eyewear'] else None

    petting = datos.get('petting') or {}
    petting_fecha = _aetherion_fecha_valida(petting.get('date'))
    try:
        petting_cantidad = max(0, min(999, int(petting.get('count', 0) or 0)))
    except (TypeError, ValueError):
        petting_cantidad = 0

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        INSERT INTO aetherion_mascota
        (id_usuario, nombre, especie, xp, hambre, felicidad, energia, racha,
         ultima_atencion, outfit_hat, outfit_neck, outfit_eyewear,
         petting_fecha, petting_cantidad)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
            nombre = VALUES(nombre),
            especie = VALUES(especie),
            xp = VALUES(xp),
            hambre = VALUES(hambre),
            felicidad = VALUES(felicidad),
            energia = VALUES(energia),
            racha = VALUES(racha),
            ultima_atencion = VALUES(ultima_atencion),
            outfit_hat = VALUES(outfit_hat),
            outfit_neck = VALUES(outfit_neck),
            outfit_eyewear = VALUES(outfit_eyewear),
            petting_fecha = VALUES(petting_fecha),
            petting_cantidad = VALUES(petting_cantidad)
    """, (
        id_usuario, nombre, especie, xp, hambre, felicidad, energia, racha,
        ultima_atencion, outfit_hat, outfit_neck, outfit_eyewear,
        petting_fecha, petting_cantidad
    ))

    # Registra los cupones de racha que el widget ya desbloqueó en el
    # navegador y que todavía no existen en la base de datos (uno por
    # hito alcanzado; el porcentaje siempre sale de AETHERION_HITOS_DESCUENTO,
    # nunca de lo que envíe el cliente).
    claimed = datos.get('claimed') or {}
    if isinstance(claimed, dict):
        for hito_str, codigo in claimed.items():
            try:
                hito = int(hito_str)
            except (TypeError, ValueError):
                continue
            if hito not in AETHERION_HITOS_DESCUENTO or racha < hito:
                continue
            codigo_limpio = re.sub(r'[^A-Z0-9-]', '', str(codigo).upper())[:30]
            if not codigo_limpio:
                continue
            cursor.execute("""
                INSERT IGNORE INTO aetherion_cupones
                (id_usuario, hito, codigo, descuento)
                VALUES (%s,%s,%s,%s)
            """, (id_usuario, hito, codigo_limpio, AETHERION_HITOS_DESCUENTO[hito]))

    conexion.commit()

    cursor.close()
    conexion.close()

    return True


def obtener_cupones_aetherion_disponibles(id_usuario):
    """Cupones de Aetherion desbloqueados por el usuario y aún sin usar,
    para poder canjearlos en el checkout."""

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT codigo, descuento, hito
        FROM aetherion_cupones
        WHERE id_usuario = %s AND usado = 0
        ORDER BY hito ASC
    """, (id_usuario,))

    filas = cursor.fetchall()

    cursor.close()
    conexion.close()

    return [{'codigo': c, 'descuento': d, 'hito': h} for c, d, h in filas]


def aplicar_cupon_aetherion(id_usuario, codigo, total):
    """Si el código pertenece a un cupón de Aetherion sin usar del usuario,
    aplica su descuento al total y lo marca como usado (funciona una única
    vez). Devuelve (total_final, porcentaje_aplicado); porcentaje_aplicado
    es None si el código no era válido."""

    if not codigo:
        return total, None

    codigo = re.sub(r'[^A-Z0-9-]', '', str(codigo).upper())[:30]

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT id_cupon, descuento
        FROM aetherion_cupones
        WHERE id_usuario = %s AND codigo = %s AND usado = 0
        FOR UPDATE
    """, (id_usuario, codigo))

    fila = cursor.fetchone()

    if fila is None:
        cursor.close()
        conexion.close()
        return total, None

    id_cupon, porcentaje = fila

    cursor.execute("""
        UPDATE aetherion_cupones
        SET usado = 1, fecha_usado = NOW()
        WHERE id_cupon = %s
    """, (id_cupon,))

    conexion.commit()

    cursor.close()
    conexion.close()

    total_final = round(float(total) * (1 - (porcentaje / 100)), 2)
    return total_final, porcentaje


# =====================================
# FAVORITOS
# =====================================

def es_favorito(id_usuario, id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT id_favorito
        FROM favoritos
        WHERE id_usuario=%s
        AND id_producto=%s
    """, (id_usuario, id_producto))

    resultado = cursor.fetchone()

    cursor.close()
    conexion.close()

    return resultado is not None


def agregar_favorito(id_usuario, id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        INSERT IGNORE INTO favoritos
        (id_usuario, id_producto)
        VALUES (%s, %s)
    """, (id_usuario, id_producto))

    conexion.commit()

    cursor.close()
    conexion.close()


def eliminar_favorito(id_usuario, id_producto):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        DELETE FROM favoritos
        WHERE id_usuario=%s
        AND id_producto=%s
    """, (id_usuario, id_producto))

    conexion.commit()

    cursor.close()
    conexion.close()


def obtener_favoritos(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            productos.id_producto,
            productos.nombre,
            productos.descripcion,
            productos.precio,
            productos.imagen,
            productos.categoria,
            productos.stock,
            favoritos.fecha_agregado
        FROM favoritos
        INNER JOIN productos
        ON favoritos.id_producto = productos.id_producto
        WHERE favoritos.id_usuario = %s
        ORDER BY favoritos.fecha_agregado DESC
    """, (id_usuario,))

    favoritos = cursor.fetchall()

    cursor.close()
    conexion.close()

    return favoritos


# =====================================
# ELIMINAR PRODUCTO DEL CARRITO
# =====================================

@app.route('/eliminar_carrito/<int:id>', methods=['POST'])
def eliminar_carrito(id):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    conexion = conectar_bd()
    cursor = conexion.cursor()

    # Se exige también id_usuario para que un usuario no pueda borrar
    # filas del carrito de otra persona cambiando el id en la URL.
    cursor.execute("""
        DELETE FROM carrito
        WHERE id_carrito=%s
        AND id_usuario=%s
    """, (id, id_usuario))

    conexion.commit()

    cursor.close()
    conexion.close()

    return redirect(url_for('carrito'))


@app.route('/actualizar_carrito/<int:id>', methods=['POST'])
def actualizar_carrito(id):
    """Actualiza o elimina una línea del carrito sin permitir acceso cruzado."""

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    try:
        cantidad = int(request.form.get('cantidad', '1'))
    except (TypeError, ValueError):
        flash('La cantidad debe ser un número entero.', 'error')
        return redirect(url_for('carrito'))

    actualizado, error = actualizar_cantidad_carrito(id_usuario, id, cantidad)

    if not actualizado:
        flash('Ese producto ya no está disponible en tu carrito.', 'error')
    elif cantidad <= 0:
        flash('Producto eliminado del carrito.', 'success')
    else:
        flash('Cantidad actualizada.', 'success')

    return redirect(url_for('carrito'))
# =====================================
# RUTAS
# =====================================



# ==========================================================
@app.route('/perfil')
def perfil():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    usuario = obtener_perfil(id_usuario)

    return render_template(
        'perfil.html',
        usuario=usuario
    )
@app.route('/agregar_carrito/<int:id>')
def agregar_al_carrito(id):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    producto_a_agregar = obtener_producto(id)

    if producto_a_agregar and producto_a_agregar[5] == 'VIP' and not es_usuario_vip(id_usuario):
        flash('Ese producto es exclusivo para miembros VIP.', 'error')
        return redirect(url_for('zona_vip'))

    agregado, error = agregar_carrito(id_usuario, id)

    if not agregado:
        flash(
            'No hay unidades disponibles de ese producto.'
            if error == 'sin_stock'
            else 'Producto no encontrado.',
            'error'
        )
        return redirect(request.referrer or url_for('productos'))

    # Fallback sin JavaScript: se queda cerca de donde estaba el usuario
    # en vez de saltar siempre al carrito.
    return redirect(request.referrer or url_for('productos'))


@app.route('/api/carrito/agregar/<int:id>', methods=['POST'])
def api_agregar_al_carrito(id):
    """Agrega un producto al carrito vía AJAX sin recargar ni redirigir la página."""

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return jsonify({'ok': False, 'error': 'login_requerido'}), 401

    producto_a_agregar = obtener_producto(id)

    if producto_a_agregar is None:
        return jsonify({'ok': False, 'error': 'producto_no_encontrado'}), 404

    if producto_a_agregar and producto_a_agregar[5] == 'VIP' and not es_usuario_vip(id_usuario):
        return jsonify({'ok': False, 'error': 'vip_requerido'}), 403

    agregado, error = agregar_carrito(id_usuario, id)

    if not agregado:
        return jsonify({'ok': False, 'error': error}), 409

    num_productos, num_unidades = contar_carrito(id_usuario)

    return jsonify({
        'ok': True,
        'num_productos': num_productos,
        'num_unidades': num_unidades
    })


@app.route('/api/carrito/contador')
def api_contador_carrito():
    """Devuelve el estado actual del contador del carrito (para sincronizar la insignia)."""

    id_usuario = session.get('id_usuario')
    num_productos, num_unidades = contar_carrito(id_usuario)

    return jsonify({
        'num_productos': num_productos,
        'num_unidades': num_unidades
    })
@app.route('/carrito')
def carrito():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    carrito_usuario = obtener_carrito(id_usuario)

    total = calcular_total(carrito_usuario)

    estado_ruleta = obtener_estado_ruleta(id_usuario)

    total_con_descuento = None

    if estado_ruleta and estado_ruleta.get('descuento_activo'):
        porcentaje = estado_ruleta['descuento_activo']
        total_con_descuento = round(float(total) * (1 - (porcentaje / 100)), 2)

    cupones_aetherion = obtener_cupones_aetherion_disponibles(id_usuario)

    return render_template(
        'carrito.html',
        carrito=carrito_usuario,
        total=total,
        estado_ruleta=estado_ruleta,
        total_con_descuento=total_con_descuento,
        cupones_aetherion=cupones_aetherion
    )
@app.route('/producto/<int:id>')
def producto(id):

    producto = obtener_producto(id)

    if producto is None:
        return "Producto no encontrado."

    id_usuario = session.get('id_usuario')

    # Un producto de la categoría VIP no debe poder verse entrando
    # directamente por la URL si el usuario no tiene la suscripción.
    if producto[5] == 'VIP' and not es_usuario_vip(id_usuario):
        flash('Ese producto es exclusivo para miembros VIP.', 'error')
        return redirect(url_for('zona_vip'))

    favorito = es_favorito(id_usuario, id) if id_usuario else False

    return render_template(
        'producto.html',
        producto=producto,
        favorito=favorito
    )


@app.route('/productos')
def productos():

    busqueda = request.args.get('q', '').strip()

    lista_productos = obtener_productos(busqueda if busqueda else None)
    productos_por_categoria = agrupar_productos_por_categoria(lista_productos)

    id_usuario = session.get('id_usuario')
    favoritos_ids = set()
    estado_ruleta = None

    if id_usuario:
        favoritos_ids = {fila[0] for fila in obtener_favoritos(id_usuario)}
        estado_ruleta = obtener_estado_ruleta(id_usuario)

    return render_template(
        'productos.html',
        productos=lista_productos,
        productos_por_categoria=productos_por_categoria,
        favoritos_ids=favoritos_ids,
        busqueda=busqueda,
        estado_ruleta=estado_ruleta
    )


# =====================================
# ZONA VIP (protegida por suscripción)
# =====================================

@app.route('/vip')
def zona_vip():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        flash('Inicia sesión para acceder a la Zona VIP.', 'error')
        return redirect(url_for('login'))

    # La validación real vive aquí, en el backend: no basta con
    # ocultar el botón/enlace en el frontend. Si alguien entra
    # directamente a /vip sin suscripción, no ve el contenido VIP.
    es_vip = es_usuario_vip(id_usuario)

    productos_vip = obtener_productos_vip() if es_vip else []

    favoritos_ids = set()
    if es_vip:
        favoritos_ids = {fila[0] for fila in obtener_favoritos(id_usuario)}

    return render_template(
        'vip_zona.html',
        es_vip=es_vip,
        vip_productos=productos_vip,
        favoritos_ids=favoritos_ids
    )


@app.route('/vip/suscribirse', methods=['POST'])
def vip_suscribirse():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    session['vip_pago_pendiente'] = True
    return redirect(url_for('pago_vip'))


@app.route('/vip/pago', methods=['GET', 'POST'])
@login_required
def pago_vip():

    if not session.get('vip_pago_pendiente'):
        return redirect(url_for('zona_vip'))

    if request.method == 'POST':
        metodo_pago = request.form.get('metodo_pago', '').strip()
        if metodo_pago not in {'Nequi', 'Daviplata'}:
            flash('Selecciona Nequi o Daviplata para continuar.', 'error')
            return redirect(url_for('pago_vip'))

        activar_suscripcion_vip(session['id_usuario'])
        session.pop('vip_pago_pendiente', None)
        flash(f'Pago registrado por {metodo_pago}. ¡Tu Zona VIP ya está activa!', 'success')
        return redirect(url_for('zona_vip'))

    return render_template('pago.html', tipo_pago='vip', total_pago=None)


@app.route('/vip/cancelar', methods=['POST'])
def vip_cancelar():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    cancelar_suscripcion_vip(id_usuario)

    flash('Tu suscripción VIP fue cancelada.', 'info')

    return redirect(url_for('zona_vip'))


# =====================================
# API DEL BUSCADOR INTELIGENTE (NAVBAR)
# =====================================

@app.route('/api/buscar_productos')
def api_buscar_productos():

    termino = request.args.get('q', '').strip()

    if len(termino) < 2:
        return jsonify([])

    resultados = buscar_productos_rapido(termino)

    productos_json = [
        {
            'id': fila[0],
            'nombre': fila[1],
            'precio': float(fila[2]),
            'imagen': url_for('static', filename='img/' + fila[3]) if fila[3] else '',
            'categoria': fila[4]
        }
        for fila in resultados
    ]

    return jsonify(productos_json)


def _normalizar_chatbot_texto(texto):
    if not texto:
        return ''
    texto = texto.lower().strip()
    texto = re.sub(r'[^a-z0-9áéíóúüñ\s]', ' ', texto)
    texto = re.sub(r'\s+', ' ', texto).strip()
    return texto


def _obtener_mascotas_usuario():
    id_usuario = session.get('id_usuario')
    if id_usuario is None:
        return []

    conexion = conectar_bd()
    cursor = conexion.cursor()
    cursor.execute(
        "SELECT nombre_mascota, tipo, raza, edad FROM mascotas WHERE id_usuario=%s ORDER BY nombre_mascota",
        (id_usuario,)
    )
    mascotas = cursor.fetchall()
    cursor.close()
    conexion.close()
    return mascotas


def _extraer_contexto_chatbot(mensaje, contexto_actual=None):
    if contexto_actual is None:
        contexto_actual = {}

    texto = _normalizar_chatbot_texto(mensaje)
    nuevo_contexto = dict(contexto_actual)

    tipos = {
        'perro': 'perro',
        'gato': 'gato',
        'conejo': 'conejo',
        'hamster': 'hamster',
        'huron': 'huron',
        'ave': 'ave',
        'pez': 'pez',
        'pajaro': 'ave',
        'loro': 'ave',
        'canario': 'ave'
    }
    for clave, valor in tipos.items():
        if clave in texto:
            nuevo_contexto['tipo'] = valor
            break

    match_edad = re.search(r'(\d{1,2})\s*(?:años|año|anios|ani)', texto)
    if match_edad:
        nuevo_contexto['edad'] = int(match_edad.group(1))

    for tamano, palabras in {
        'pequeño': ['pequeno', 'pequeño', 'pequena', 'pequeña', 'mini', 'miniatura'],
        'mediano': ['mediano', 'mediana', 'tamano medio', 'tamaño medio'],
        'grande': ['grande', 'gigante', 'grueso', 'pesado']
    }.items():
        if any(palabra in texto for palabra in palabras):
            nuevo_contexto['tamano'] = tamano
            break

    if 'alimento' in texto or 'comida' in texto or 'croquetas' in texto or 'pienso' in texto:
        nuevo_contexto['necesidad'] = 'alimento'
    elif 'juguete' in texto or 'pelota' in texto or 'juego' in texto:
        nuevo_contexto['necesidad'] = 'juguete'
    elif 'accesorio' in texto or 'correa' in texto or 'collar' in texto or 'arnes' in texto:
        nuevo_contexto['necesidad'] = 'accesorio'
    elif 'higiene' in texto or 'baño' in texto or 'limpieza' in texto or 'shampoo' in texto:
        nuevo_contexto['necesidad'] = 'higiene'
    elif 'entrenamiento' in texto or 'adiestramiento' in texto:
        nuevo_contexto['necesidad'] = 'entrenamiento'
    elif 'cuidado' in texto or 'salud' in texto or 'medicina' in texto:
        nuevo_contexto['necesidad'] = 'cuidado'

    if 'presupuesto' in texto or 'precio' in texto or 'cuanto' in texto or 'cuánto' in texto:
        nuevo_contexto['presupuesto'] = 'importante'

    return nuevo_contexto


def _obtener_productos_chatbot(categoria=None, tipo_mascota=None, limite=4):
    conexion = conectar_bd()
    cursor = conexion.cursor()

    condiciones = ["categoria <> 'VIP'"]
    parametros = []

    if categoria:
        condiciones.append("categoria = %s")
        parametros.append(categoria)

    if tipo_mascota:
        condiciones.append("(LOWER(COALESCE(nombre, '')) LIKE %s OR LOWER(COALESCE(descripcion, '')) LIKE %s OR LOWER(COALESCE(categoria, '')) LIKE %s)")
        patron = f"%{tipo_mascota}%"
        parametros.extend([patron, patron, patron])

    sql = f"""
        SELECT id_producto, nombre, descripcion, precio, imagen, categoria, stock
        FROM productos
        WHERE {' AND '.join(condiciones)}
        ORDER BY stock DESC, nombre
        LIMIT %s
    """
    parametros.append(limite)

    cursor.execute(sql, tuple(parametros))
    productos = cursor.fetchall()
    cursor.close()
    conexion.close()
    return productos


def _mapear_intencion_producto(mensaje):
    texto = _normalizar_chatbot_texto(mensaje)

    mapeo = {
        'Alimentos': ['alimento', 'comida', 'croqueta', 'croquetas', 'pienso', 'food'],
        'Juguetes': ['juguete', 'juguetes', 'pelota', 'juego', 'entretenimiento', 'puzzle'],
        'Accesorios': ['accesorio', 'correa', 'arnes', 'collar', 'ropa', 'accesorios'],
        'Higiene': ['higiene', 'baño', 'limpieza', 'aseo', 'shampoo', 'champu'],
        'Salud': ['salud', 'vitamina', 'medicina', 'antipulgas', 'calma', 'cuidado']
    }

    for categoria, palabras in mapeo.items():
        if any(palabra in texto for palabra in palabras):
            return categoria

    if 'entrenamiento' in texto or 'adiestramiento' in texto:
        return 'Accesorios'

    return None


@app.route('/api/chatbot', methods=['POST'])
def api_chatbot():
    """Asistente inteligente de Animalum con contexto de mascota y recomendaciones reales del catálogo."""

    datos = request.get_json(silent=True) or {}
    mensaje = str(datos.get('mensaje', '')).strip()
    if not mensaje:
        return jsonify({
            'respuesta': 'Escribe una pregunta sobre tu mascota o los productos de Animalum.',
            'productos': [],
            'tipo': 'info'
        })

    contexto = session.get('chatbot_context', {}) or {}
    contexto = _extraer_contexto_chatbot(mensaje, contexto)

    if not contexto.get('tipo'):
        mascotas = _obtener_mascotas_usuario()
        if mascotas:
            _, tipo_mascota, _, edad_mascota = mascotas[0]
            contexto.setdefault('tipo', str(tipo_mascota).lower())
            if edad_mascota is not None and contexto.get('edad') is None:
                contexto['edad'] = int(edad_mascota)

    session['chatbot_context'] = contexto

    texto = _normalizar_chatbot_texto(mensaje)

    if not texto:
        return jsonify({
            'respuesta': 'Necesito que me digas qué está buscando para tu mascota.',
            'productos': [],
            'tipo': 'seguimiento'
        })

    if any(palabra in texto for palabra in ['enfermedad', 'vomita', 'diarrea', 'fiebre', 'dolor', 'medicamento', 'tratamiento', 'sintoma', 'drogas']):
        return jsonify({
            'respuesta': 'Para temas de salud, medicamentos o síntomas graves, la recomendación general es consultar a un veterinario. Puedo ayudarte con productos de cuidado general, pero no puedo diagnosticar ni indicar tratamientos médicos.',
            'productos': [],
            'tipo': 'salud'
        })

    if any(palabra in texto for palabra in ['precio', 'cuanto cuesta', 'cuánto cuesta', 'costo', 'valor', 'descuento', 'promocion', 'promoción', 'cupon', 'cupón', 'envio', 'envío', 'metodo de pago', 'método de pago', 'pedido', 'entrega']):
        faq = (
            'En Animalum puedes encontrar productos de alimentos, juguetes, accesorios e higiene para perros, gatos y otras mascotas. '
            'Los precios varían según la categoría y la disponibilidad del inventario. Si necesitas ayuda con un producto específico, te puedo recomendar opciones de acuerdo a tu mascota. '
            'Los pedidos se gestionan desde nuestra plataforma y los pagos se realizan con los métodos habilitados en la tienda.'
        )
        return jsonify({
            'respuesta': faq,
            'productos': [],
            'tipo': 'faq'
        })

    if any(palabra in texto for palabra in ['hola', 'buenas', 'buenos', 'buenas tardes', 'buenas noches', 'hi', 'hey']):
        return jsonify({
            'respuesta': '¡Hola! Soy el asistente de Animalum. Cuéntame qué mascota tienes, qué necesitas y te recomendaré productos útiles y adecuados.',
            'productos': [],
            'tipo': 'saludo'
        })

    categoria = _mapear_intencion_producto(texto)
    productos = []

    if categoria:
        productos = _obtener_productos_chatbot(categoria=categoria, tipo_mascota=contexto.get('tipo'), limite=3)
    elif 'producto' in texto or 'comprar' in texto or 'recomienda' in texto or 'productos' in texto:
        productos = _obtener_productos_chatbot(tipo_mascota=contexto.get('tipo'), limite=4)
    else:
        productos = _obtener_productos_chatbot(limite=3)

    if categoria and not contexto.get('tipo') and not any(palabra in texto for palabra in ['perro', 'gato', 'conejo', 'hamster', 'ave', 'pez']):
        return jsonify({
            'respuesta': 'Para recomendarte mejor, dime qué tipo de mascota tienes, su edad aproximada y si buscas algo específico como alimento, juguetes o higiene.',
            'productos': [],
            'tipo': 'seguimiento'
        })

    descripcion_contexto = []
    if contexto.get('tipo'):
        descripcion_contexto.append(f"{contexto['tipo']}")
    if contexto.get('edad') is not None:
        descripcion_contexto.append(f"de {contexto['edad']} años")
    if contexto.get('tamano'):
        descripcion_contexto.append(f"de tamaño {contexto['tamano']}")
    if contexto.get('necesidad'):
        descripcion_contexto.append(f"buscando {contexto['necesidad']}")

    contexto_texto = ', '.join(descripcion_contexto) if descripcion_contexto else 'tu mascota'

    if productos:
        productos_json = []
        for id_producto, nombre, descripcion, precio, imagen, categoria_producto, stock in productos:
            productos_json.append({
                'id': id_producto,
                'nombre': nombre,
                'descripcion': descripcion or 'Producto disponible en Animalum.',
                'precio': float(precio),
                'imagen': url_for('static', filename='img/' + imagen) if imagen else '',
                'categoria': categoria_producto,
                'stock': int(stock),
                'disponible': int(stock) > 0,
                'url': url_for('producto', id=id_producto)
            })

        if categoria:
            respuesta = (
                f'Perfecto. Para {contexto_texto}, te recomiendo revisar estos productos de {categoria} en Animalum. '
                'Puedo ayudarte con opciones más precisas si me dices presupuesto o necesidades adicionales.'
            )
        else:
            respuesta = (
                f'He revisado lo que buscas para {contexto_texto}. Te recomiendo estas opciones del catálogo de Animalum para que elijas la mejor para tu mascota.'
            )

        return jsonify({
            'respuesta': respuesta,
            'productos': productos_json,
            'tipo': 'recomendacion'
        })

    return jsonify({
        'respuesta': 'No encontré productos exactos para esa búsqueda, pero puedo ayudarte a elegir según la especie, edad y necesidades de tu mascota. Si quieres, dime más detalles y te sugiero opciones reales del catálogo.',
        'productos': [],
        'tipo': 'seguimiento'
    })


# =====================================
# API DE LA RULETA DE DESCUENTOS
# =====================================

@app.route('/ruleta/estado')
@login_required
def ruleta_estado():

    estado = obtener_estado_ruleta(session.get('id_usuario'))

    if estado is None:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    return jsonify(estado)


@app.route('/ruleta/girar', methods=['POST'])
@login_required
def ruleta_girar():

    id_usuario = session.get('id_usuario')

    premio = girar_ruleta(id_usuario)

    if premio is None:
        estado = obtener_estado_ruleta(id_usuario)
        return jsonify({
            'ok': False,
            'mensaje': 'La ruleta no está disponible en este momento.',
            'estado': estado
        }), 400

    return jsonify({
        'ok': True,
        'descuento': premio,
        'mensaje': f'¡Ganaste un {premio}% de descuento para tu próxima compra!'
    })


# =====================================
# RUTAS Y API DE AETHERION
# =====================================

@app.route('/aetherion')
@login_required
def aetherion():
    return render_template('aetherion.html')


@app.route('/api/aetherion/estado', methods=['GET'])
@login_required
def api_aetherion_obtener_estado():

    estado = obtener_estado_aetherion(session.get('id_usuario'))

    return jsonify(estado)


@app.route('/api/aetherion/estado', methods=['POST'])
@login_required
def api_aetherion_guardar_estado():

    datos = request.get_json(silent=True)

    if datos is None:
        return jsonify({'ok': False, 'error': 'JSON inválido'}), 400

    guardar_estado_aetherion(session.get('id_usuario'), datos)

    return jsonify({'ok': True})


# =====================================
# RUTAS DE FAVORITOS
# =====================================

@app.route('/favoritos')
@login_required
def favoritos():

    id_usuario = session.get('id_usuario')

    lista_favoritos = obtener_favoritos(id_usuario)

    return render_template(
        'favoritos.html',
        favoritos=lista_favoritos
    )


@app.route('/favoritos/agregar/<int:id>', methods=['POST'])
@login_required
def agregar_a_favoritos(id):

    id_usuario = session.get('id_usuario')

    producto_existente = obtener_producto(id)

    if producto_existente is None:
        flash("Producto no encontrado.", "error")
        return redirect(url_for('productos'))

    agregar_favorito(id_usuario, id)

    flash("Producto agregado a tus favoritos.", "success")
    return redirect(request.referrer or url_for('productos'))


@app.route('/favoritos/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_de_favoritos(id):

    id_usuario = session.get('id_usuario')

    eliminar_favorito(id_usuario, id)

    flash("Producto eliminado de tus favoritos.", "success")
    return redirect(request.referrer or url_for('favoritos'))

@app.route('/historial_facturas')
def historial_facturas():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    facturas = obtener_facturas_usuario(id_usuario)

    return render_template(
        'factura_historial.html',
        facturas=facturas
    )

@app.route('/envios')
def envios():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    cupones_aetherion = obtener_cupones_aetherion_disponibles(id_usuario)

    return render_template('envios.html', cupones_aetherion=cupones_aetherion)

@app.route('/terminos-condiciones')
def terminos():
    return render_template('terminos.html')

@app.route('/politica-privacidad')
def privacidad():
    return render_template('privacidad.html')

@app.route('/')
def inicio():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/registro')
def registro():
    return render_template('registro.html')

@app.route('/contacto')
def contacto():
    return render_template('contactos.html')

@app.route('/usuarios')
@admin_required
def mostrar_usuarios():

    id_usuario = session.get('id_usuario')

    usuarios = obtener_usuarios()

    return render_template(
        'usuarios.html',
        usuarios=usuarios,
        usuario_logueado=id_usuario,
        id_usuario=id_usuario
    )


@app.route('/admin/usuarios/rol/<int:id>', methods=['POST'])
@admin_required
def cambiar_rol_usuario(id):

    if id == session.get('id_usuario'):
        flash("No puedes cambiar tu propio rol.", "error")
        return redirect(url_for('mostrar_usuarios'))

    alternar_rol_usuario(id)

    flash("Rol del usuario actualizado correctamente.", "success")
    return redirect(url_for('mostrar_usuarios'))



@app.route('/exito')
def exito():
    return render_template('exito.html')

# =====================================
# REGISTRO
# =====================================

@app.route('/procesar_registro', methods=['POST'])
def procesar_registro():

    nombre = request.form.get('nombre', '').strip()
    apellido = request.form.get('apellido', '').strip()
    correo = request.form.get('correo', '').strip()
    direccion = request.form.get('direccion', '').strip()
    password = request.form.get('password', '').strip()

    nombres_mascotas = request.form.getlist('nombre_mascota[]')
    tipos_mascotas = request.form.getlist('tipo_mascota[]')
    razas_mascotas = request.form.getlist('raza_mascota[]')
    edades_mascotas = request.form.getlist('edad_mascota[]')

    if not all([nombre, apellido, correo, direccion, password]):
        return "Todos los campos son obligatorios.", 400

    cantidad_mascotas = len(nombres_mascotas)
    if not 1 <= cantidad_mascotas <= 10:
        return "Debes registrar entre 1 y 10 mascotas.", 400

    if not (
        len(tipos_mascotas) == cantidad_mascotas
        and len(razas_mascotas) == cantidad_mascotas
        and len(edades_mascotas) == cantidad_mascotas
    ):
        return "La información de las mascotas está incompleta.", 400

    mascotas = []
    for indice in range(cantidad_mascotas):
        nombre_mascota = nombres_mascotas[indice].strip()
        tipo = tipos_mascotas[indice].strip()
        raza = razas_mascotas[indice].strip()
        edad_texto = edades_mascotas[indice].strip()

        if not nombre_mascota or not tipo or not edad_texto:
            return f"Completa todos los campos obligatorios de la mascota {indice + 1}.", 400

        try:
            edad = int(edad_texto)
        except ValueError:
            return f"La edad de la mascota {indice + 1} debe ser un número entero.", 400

        if edad < 0 or edad > 40:
            return f"La edad de la mascota {indice + 1} debe estar entre 0 y 40 años.", 400

        mascotas.append({
            'nombre': nombre_mascota,
            'tipo': tipo,
            'raza': raza,
            'edad': edad
        })

    if correo_existe(correo):
        return "Este correo ya está registrado. Intenta con otro.", 400

    registrar_usuario_con_mascotas(
        nombre,
        apellido,
        correo,
        direccion,
        password,
        mascotas
    )

    return redirect(url_for('exito'))

# =====================================
# CONTACTO
# =====================================

@app.route('/procesar_contacto', methods=['POST'])
def procesar_contacto():

    nombre = request.form.get('nombre', '').strip()
    correo = request.form.get('correo', '').strip()
    telefono = request.form.get('telefono', '').strip()
    asunto = request.form.get('asunto', '').strip()
    mensaje = request.form.get('mensaje', '').strip()

    if not all([nombre, correo, telefono, asunto, mensaje]):
        flash("Todos los campos del formulario son obligatorios.", "error")
        return redirect(url_for('contacto'))

    insertar_contacto(
        nombre,
        correo,
        telefono,
        asunto,
        mensaje
    )

    enviar_correo_contacto(nombre, correo, telefono, asunto, mensaje)

    flash("¡Tu mensaje ha sido enviado exitosamente! Pronto nos pondremos en contacto.", "success")
    return redirect(url_for('contacto'))



# =====================================
# PROCESAR ENVIO
# =====================================

@app.route('/procesar_envio', methods=['POST'])
def procesar_envio():

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    nombre_receptor = request.form.get('nombre', '').strip()
    telefono = request.form.get('telefono', '').strip()
    direccion = request.form.get('direccion', '').strip()
    ciudad = request.form.get('ciudad', '').strip()
    departamento = request.form.get('departamento', '').strip()
    codigo_postal = request.form.get('codigo_postal', '').strip()
    metodo_pago = request.form.get('metodo_pago', '').strip()
    observaciones = request.form.get('observaciones', '').strip()

    if not all([nombre_receptor, telefono, direccion, ciudad, departamento, metodo_pago]):
        return "Todos los campos del formulario de envío son obligatorios.", 400

    if metodo_pago not in {'Nequi', 'Daviplata'}:
        flash('Por ahora solo aceptamos pagos por Nequi o Daviplata.', 'error')
        return redirect(url_for('envios'))

    carrito_usuario = obtener_carrito(id_usuario)

    if not carrito_usuario:
        return "Tu carrito está vacío. Agrega productos antes de confirmar el pedido.", 400

    total = calcular_total(carrito_usuario)
    codigo_cupon_aetherion = request.form.get('codigo_cupon_aetherion', '').strip()

    session['pedido_pago_pendiente'] = {
        'nombre_receptor': nombre_receptor,
        'telefono': telefono,
        'direccion': direccion,
        'ciudad': ciudad,
        'departamento': departamento,
        'codigo_postal': codigo_postal,
        'metodo_pago': metodo_pago,
        'observaciones': observaciones,
        'codigo_cupon_aetherion': codigo_cupon_aetherion,
        'total': float(total)
    }

    return redirect(url_for('pago_pedido'))


@app.route('/pago', methods=['GET', 'POST'])
@login_required
def pago_pedido():

    pedido = session.get('pedido_pago_pendiente')
    if not pedido:
        return redirect(url_for('carrito'))

    if request.method == 'POST':
        metodo_pago = request.form.get('metodo_pago', '').strip()
        if metodo_pago not in {'Nequi', 'Daviplata'}:
            flash('Selecciona Nequi o Daviplata para continuar.', 'error')
            return redirect(url_for('pago_pedido'))

        id_usuario = session['id_usuario']
        carrito_usuario = obtener_carrito(id_usuario)
        if not carrito_usuario:
            session.pop('pedido_pago_pendiente', None)
            flash('Tu carrito está vacío.', 'error')
            return redirect(url_for('carrito'))

        total, descuento_aplicado = aplicar_descuento_ruleta(id_usuario, calcular_total(carrito_usuario))
        observaciones = pedido['observaciones']
        if descuento_aplicado:
            nota = f"Descuento de ruleta aplicado: -{descuento_aplicado}%"
            observaciones = f"{observaciones} | {nota}" if observaciones else nota
        else:
            total, descuento_aetherion = aplicar_cupon_aetherion(
                id_usuario, pedido['codigo_cupon_aetherion'], total
            )
            if descuento_aetherion:
                nota = f"Cupón de Aetherion aplicado: -{descuento_aetherion}%"
                observaciones = f"{observaciones} | {nota}" if observaciones else nota

        id_envio = insertar_envio(
            id_usuario, pedido['nombre_receptor'], pedido['telefono'], pedido['direccion'],
            pedido['ciudad'], pedido['departamento'], pedido['codigo_postal'], metodo_pago,
            observaciones
        )
        id_factura = insertar_factura(id_usuario, id_envio, total, metodo_pago, observaciones)
        insertar_items_factura(id_factura, carrito_usuario)
        vaciar_carrito_usuario(id_usuario)
        registrar_compra_ruleta(id_usuario)
        session.pop('pedido_pago_pendiente', None)
        return redirect(url_for('factura', id_factura=id_factura))

    return render_template('pago.html', tipo_pago='pedido', total_pago=pedido['total'])


@app.route('/factura/<int:id_factura>')
def factura(id_factura):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        return redirect(url_for('login'))

    factura = obtener_factura(id_factura, id_usuario)
    items = obtener_items_factura(id_factura)

    if factura is None:
        return "Factura no encontrada.", 404

    factura_data = {
        'id': factura[0],
        'total': factura[1],
        'fecha': factura[2],
        'estado': factura[3],
        'metodo_pago': factura[4],
        'observaciones': factura[5],
        'nombre_receptor': factura[6],
        'telefono': factura[7],
        'direccion': factura[8],
        'ciudad': factura[9],
        'departamento': factura[10],
        'codigo_postal': factura[11],
        'nombre': factura[12],
        'apellido': factura[13],
        'correo': factura[14]
    }

    return render_template(
        'factura.html',
        factura=factura_data,
        items=items
    )


@app.route('/procesar_login', methods=['POST'])
def procesar_login():

    correo = request.form.get('correo', '').strip()
    password = request.form.get('password', '').strip()

    if not correo or not password:
        flash("Correo y contraseña son obligatorios.", "error")
        return redirect(url_for('login'))

    conexion = conectar_bd()
    cursor = conexion.cursor()

    sql = """
    SELECT id_usuario, nombre, apellido, correo, direccion, password, rol
    FROM usuarios
    WHERE correo = %s
    """

    cursor.execute(sql, (correo,))

    usuario = cursor.fetchone()

    cursor.close()
    conexion.close()

    if usuario and check_password_hash(usuario[5], password):

        session['id_usuario'] = usuario[0]
        session['nombre'] = usuario[1]
        session['rol'] = usuario[6]

        flash(f"¡Bienvenido de nuevo, {usuario[1]}!", "success")

        if usuario[6] == 'admin':
            return redirect(url_for('admin_panel'))

        return redirect(url_for('inicio'))

    flash("Correo o contraseña incorrectos.", "error")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Has cerrado sesión exitosamente.", "success")
    return redirect(url_for('inicio'))

# =====================================
# RECUPERAR CONTRASEÑA
# =====================================

@app.route('/recuperar-password')
def recuperar_password():
    return render_template('recuperar_password.html')


@app.route('/procesar_recuperar_password', methods=['POST'])
def procesar_recuperar_password():

    correo = request.form.get('correo', '').strip()

    if not correo:
        flash("Debes ingresar tu correo electrónico.", "error")
        return redirect(url_for('recuperar_password'))

    token = generar_token_reset(correo)

    if token:
        enviar_correo_recuperacion(correo, token)

    # Por seguridad se muestra siempre el mismo mensaje, exista o no el
    # correo en la base de datos (para no revelar qué correos están registrados).
    flash(
        "Si el correo está registrado, te hemos enviado un enlace para restablecer tu contraseña.",
        "success"
    )
    return redirect(url_for('login'))


@app.route('/restablecer-password/<token>')
def restablecer_password(token):

    usuario = obtener_usuario_por_token(token)

    if not usuario:
        flash("El enlace de recuperación no es válido o ha expirado. Solicita uno nuevo.", "error")
        return redirect(url_for('recuperar_password'))

    return render_template('restablecer_password.html', token=token)


@app.route('/procesar_restablecer_password', methods=['POST'])
def procesar_restablecer_password():

    token = request.form.get('token', '').strip()
    password = request.form.get('password', '').strip()
    confirmar_password = request.form.get('confirmar_password', '').strip()

    usuario = obtener_usuario_por_token(token)

    if not usuario:
        flash("El enlace de recuperación no es válido o ha expirado. Solicita uno nuevo.", "error")
        return redirect(url_for('recuperar_password'))

    if not password or not confirmar_password:
        flash("Debes completar ambos campos de contraseña.", "error")
        return redirect(url_for('restablecer_password', token=token))

    if password != confirmar_password:
        flash("Las contraseñas no coinciden.", "error")
        return redirect(url_for('restablecer_password', token=token))

    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.", "error")
        return redirect(url_for('restablecer_password', token=token))

    actualizar_password_usuario(usuario['id_usuario'], password)

    flash("Tu contraseña se actualizó correctamente. Ya puedes iniciar sesión.", "success")
    return redirect(url_for('login'))

@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
def eliminar_usuario(id):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        flash("Debes iniciar sesión para realizar esta acción.", "error")
        return redirect(url_for('login'))

    # Solo permitir que el usuario elimine su propia cuenta o si es admin
    if id_usuario != id and session.get('rol') != 'admin':
        flash("No tienes permiso para realizar esta acción.", "error")
        return redirect(url_for('perfil'))

    conexion = conectar_bd()
    cursor = conexion.cursor()

    # Eliminar primero la mascota del usuario
    cursor.execute(
        "DELETE FROM mascotas WHERE id_usuario=%s",
        (id,)
    )

    # Luego eliminar el usuario
    cursor.execute(
        "DELETE FROM usuarios WHERE id_usuario=%s",
        (id,)
    )

    conexion.commit()

    cursor.close()
    conexion.close()

    if id_usuario == id:
        session.clear()
        flash("Tu cuenta ha sido eliminada.", "success")
        return redirect(url_for('inicio'))

    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('mostrar_usuarios'))

@app.route('/actualizar_usuario/<int:id>', methods=['GET'])
def mostrar_formulario_actualizar_usuario(id):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        flash("Debes iniciar sesión para realizar esta acción.", "error")
        return redirect(url_for('login'))

    if id_usuario != id and session.get('rol') != 'admin':
        flash("No tienes permiso para realizar esta acción.", "error")
        return redirect(url_for('perfil'))

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            nombre,
            apellido,
            correo,
            direccion
        FROM usuarios
        WHERE id_usuario=%s
    """, (id,))

    usuario = cursor.fetchone()

    cursor.close()
    conexion.close()

    if usuario is None:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for('mostrar_usuarios'))

    return render_template(
        'actualizar_usuario.html',
        id=id,
        nombre=usuario[0],
        apellido=usuario[1],
        correo=usuario[2],
        direccion=usuario[3]
    )

@app.route('/actualizar_usuario/<int:id>', methods=['POST'])
def actualizar_usuario(id):

    id_usuario = session.get('id_usuario')

    if id_usuario is None:
        flash("Debes iniciar sesión para realizar esta acción.", "error")
        return redirect(url_for('login'))

    if id_usuario != id and session.get('rol') != 'admin':
        flash("No tienes permiso para realizar esta acción.", "error")
        return redirect(url_for('perfil'))

    nuevo_nombre = request.form.get('nuevo_nombre', '').strip()
    nuevo_apellido = request.form.get('nuevo_apellido', '').strip()
    nuevo_correo = request.form.get('nuevo_correo', '').strip()
    nueva_direccion = request.form.get('nueva_direccion', '').strip()
    nueva_password = request.form.get('nueva_password', '').strip()

    if not all([nuevo_nombre, nuevo_apellido, nuevo_correo, nueva_direccion]):
        flash("Nombre, apellido, correo y dirección son obligatorios.", "error")
        return redirect(url_for('mostrar_formulario_actualizar_usuario', id=id))

    if correo_ocupado(nuevo_correo, id):
        flash("Ese correo ya está registrado por otro usuario.", "error")
        return redirect(url_for('mostrar_formulario_actualizar_usuario', id=id))

    conexion = conectar_bd()
    cursor = conexion.cursor()

    if nueva_password:

        password_hash = generate_password_hash(nueva_password)

        cursor.execute("""
            UPDATE usuarios
            SET
                nombre=%s,
                apellido=%s,
                correo=%s,
                direccion=%s,
                password=%s
            WHERE id_usuario=%s
        """, (
            nuevo_nombre,
            nuevo_apellido,
            nuevo_correo,
            nueva_direccion,
            password_hash,
            id
        ))

    else:

        cursor.execute("""
            UPDATE usuarios
            SET
                nombre=%s,
                apellido=%s,
                correo=%s,
                direccion=%s
            WHERE id_usuario=%s
        """, (
            nuevo_nombre,
            nuevo_apellido,
            nuevo_correo,
            nueva_direccion,
            id
        ))

    conexion.commit()

    cursor.close()
    conexion.close()

    if id_usuario == id:
        session['nombre'] = nuevo_nombre

    flash("Datos actualizados correctamente.", "success")

    if session.get('rol') == 'admin':
        return redirect(url_for('mostrar_usuarios'))

    return redirect(url_for('perfil'))


# =====================================
# OBTENER PERFIL
# =====================================

def obtener_perfil(id_usuario):

    conexion = conectar_bd()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT
            nombre,
            apellido,
            correo,
            direccion
        FROM usuarios
        WHERE id_usuario = %s
    """, (id_usuario,))

    usuario = cursor.fetchone()

    cursor.close()
    conexion.close()

    return usuario


# =====================================
# ESTADÍSTICAS (ADMINISTRADOR)
# =====================================

def obtener_estadisticas():

    conexion = conectar_bd()
    cursor = conexion.cursor()

    # Totales generales de ventas
    cursor.execute("""
        SELECT
            COUNT(*),
            COALESCE(SUM(total), 0),
            COALESCE(AVG(total), 0)
        FROM facturas
    """)
    total_pedidos, total_ventas, ticket_promedio = cursor.fetchone()

    # Usuarios por rol
    cursor.execute("""
        SELECT
            COUNT(*),
            SUM(CASE WHEN rol = 'admin' THEN 1 ELSE 0 END),
            SUM(CASE WHEN rol = 'cliente' THEN 1 ELSE 0 END)
        FROM usuarios
    """)
    total_usuarios, total_admins, total_clientes = cursor.fetchone()

    # Ventas agrupadas por mes (últimos 6 meses con ventas)
    cursor.execute("""
        SELECT
            DATE_FORMAT(fecha, '%%Y-%%m') AS mes,
            COUNT(*) AS pedidos,
            SUM(total) AS total
        FROM facturas
        GROUP BY mes
        ORDER BY mes DESC
        LIMIT 6
    """)
    ventas_por_mes = cursor.fetchall()

    # Productos más vendidos (por unidades)
    cursor.execute("""
        SELECT
            nombre_producto,
            SUM(cantidad) AS unidades,
            SUM(subtotal) AS total
        FROM factura_items
        GROUP BY nombre_producto
        ORDER BY unidades DESC
        LIMIT 5
    """)
    productos_top = cursor.fetchall()

    # Pedidos por estado
    cursor.execute("""
        SELECT estado, COUNT(*)
        FROM facturas
        GROUP BY estado
    """)
    pedidos_por_estado = cursor.fetchall()

    # Últimos pedidos realizados
    cursor.execute("""
        SELECT
            f.id_factura,
            u.nombre,
            u.apellido,
            f.total,
            f.estado,
            f.fecha
        FROM facturas f
        INNER JOIN usuarios u ON f.id_usuario = u.id_usuario
        ORDER BY f.fecha DESC
        LIMIT 10
    """)
    ultimos_pedidos = cursor.fetchall()

    # Productos más agregados a favoritos
    cursor.execute("""
        SELECT
            p.nombre,
            COUNT(*) AS veces
        FROM favoritos fav
        INNER JOIN productos p ON fav.id_producto = p.id_producto
        GROUP BY p.nombre
        ORDER BY veces DESC
        LIMIT 5
    """)
    productos_favoritos_top = cursor.fetchall()

    cursor.close()
    conexion.close()

    return {
        'total_pedidos': total_pedidos,
        'total_ventas': total_ventas,
        'ticket_promedio': ticket_promedio,
        'total_usuarios': total_usuarios,
        'total_admins': total_admins or 0,
        'total_clientes': total_clientes or 0,
        'ventas_por_mes': ventas_por_mes,
        'productos_top': productos_top,
        'pedidos_por_estado': pedidos_por_estado,
        'ultimos_pedidos': ultimos_pedidos,
        'productos_favoritos_top': productos_favoritos_top
    }


# =====================================
# PANEL DE ADMINISTRADOR
# =====================================

@app.route('/admin')
@admin_required
def admin_panel():

    total_productos = len(obtener_productos())
    total_usuarios = len(obtener_usuarios())

    return render_template(
        'admin_dashboard.html',
        total_productos=total_productos,
        total_usuarios=total_usuarios
    )


@app.route('/admin/estadisticas')
@admin_required
def admin_estadisticas():

    estadisticas = obtener_estadisticas()

    return render_template(
        'admin_estadisticas.html',
        stats=estadisticas
    )


@app.route('/admin/mensajes')
@admin_required
def admin_mensajes():

    mensajes = obtener_contactos()

    return render_template(
        'admin_contactos.html',
        mensajes=mensajes
    )


@app.route('/admin/productos')
@admin_required
def admin_productos():

    lista_productos = obtener_productos()

    return render_template(
        'admin_productos.html',
        productos=lista_productos
    )


@app.route('/admin/productos/nuevo', methods=['GET', 'POST'])
@admin_required
def admin_nuevo_producto():

    if request.method == 'GET':
        return render_template('admin_producto_form.html', producto=None)

    nombre = request.form.get('nombre', '').strip()
    descripcion = request.form.get('descripcion', '').strip()
    categoria = request.form.get('categoria', '').strip()
    precio_texto = request.form.get('precio', '').strip()
    stock_texto = request.form.get('stock', '').strip()
    archivo = request.files.get('imagen')

    if not all([nombre, descripcion, categoria, precio_texto, stock_texto]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('admin_nuevo_producto'))

    if archivo is None or archivo.filename == '':
        flash("Debes subir una imagen para el producto.", "error")
        return redirect(url_for('admin_nuevo_producto'))

    if not extension_permitida(archivo.filename):
        flash("Formato de imagen no permitido. Usa jpg, jpeg, png o webp.", "error")
        return redirect(url_for('admin_nuevo_producto'))

    try:
        precio = float(precio_texto)
        stock = int(stock_texto)
    except ValueError:
        flash("El precio y el stock deben ser valores numéricos.", "error")
        return redirect(url_for('admin_nuevo_producto'))

    if precio < 0 or stock < 0:
        flash("El precio y el stock no pueden ser negativos.", "error")
        return redirect(url_for('admin_nuevo_producto'))

    nombre_imagen = guardar_imagen_producto(archivo)

    insertar_producto(nombre, descripcion, precio, nombre_imagen, categoria, stock)

    flash("Producto creado exitosamente.", "success")
    return redirect(url_for('admin_productos'))


@app.route('/admin/productos/editar/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_editar_producto(id):

    producto_actual = obtener_producto(id)

    if producto_actual is None:
        flash("Producto no encontrado.", "error")
        return redirect(url_for('admin_productos'))

    if request.method == 'GET':
        return render_template('admin_producto_form.html', producto=producto_actual)

    nombre = request.form.get('nombre', '').strip()
    descripcion = request.form.get('descripcion', '').strip()
    categoria = request.form.get('categoria', '').strip()
    precio_texto = request.form.get('precio', '').strip()
    stock_texto = request.form.get('stock', '').strip()
    archivo = request.files.get('imagen')

    if not all([nombre, descripcion, categoria, precio_texto, stock_texto]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('admin_editar_producto', id=id))

    try:
        precio = float(precio_texto)
        stock = int(stock_texto)
    except ValueError:
        flash("El precio y el stock deben ser valores numéricos.", "error")
        return redirect(url_for('admin_editar_producto', id=id))

    if precio < 0 or stock < 0:
        flash("El precio y el stock no pueden ser negativos.", "error")
        return redirect(url_for('admin_editar_producto', id=id))

    nombre_imagen = None

    if archivo is not None and archivo.filename != '':

        if not extension_permitida(archivo.filename):
            flash("Formato de imagen no permitido. Usa jpg, jpeg, png o webp.", "error")
            return redirect(url_for('admin_editar_producto', id=id))

        nombre_imagen = guardar_imagen_producto(archivo)

    actualizar_producto(id, nombre, descripcion, precio, categoria, stock, imagen=nombre_imagen)

    flash("Producto actualizado exitosamente.", "success")
    return redirect(url_for('admin_productos'))


@app.route('/admin/productos/eliminar/<int:id>', methods=['POST'])
@admin_required
def admin_eliminar_producto(id):

    eliminar_producto(id)

    flash("Producto eliminado correctamente.", "success")
    return redirect(url_for('admin_productos'))


# =====================================
# EJECUTAR
# =====================================

if __name__ == '__main__':
    app.run(debug=True)






# =====================================
# EJECUTAR
# =====================================

if __name__ == '__main__':
    app.run(debug=True)

