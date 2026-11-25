"""Integra el agente de Groq con las consultas autorizadas de LUNARA.

Este módulo construye las instrucciones del chat, declara las herramientas que el modelo
puede solicitar y ejecuta esas herramientas contra MySQL después de validar sus datos.
La aplicación Flask envía aquí la pregunta y el contexto del usuario; el modelo no abre
una conexión a la base ni ejecuta código Python directamente.
"""

import json
import os
import re
import secrets
from pathlib import Path

from dotenv import load_dotenv

from db import get_connection

# Carga la configuracion del agente desde el archivo env
load_dotenv(Path(__file__).with_name('.env'))

# en dado caso que se ejecute en otra maquina instala el SDK de Groq
try:
    from groq import Groq
except ImportError:  # pragma: no cover
    Groq = None

# agregamos la lista de tablas que el agente puede consultar y modificar
ADMIN_TABLES = {'user', 'client', 'membership', 'contract', 'payment'}
# esto sirve para que el agente ia no pida datos sensibles como contrasenas tokens o hashes
SENSITIVE_COLUMN_MARKERS = ('password', 'secret', 'token', 'hash', 'credential')

# roles de usuario que el agente puede reconocer
SUPPORTED_USER_ROLES = (
    'Administrador',
    'Gerente',
    'Gestor de Membresías',
    'Empleado',
    'Usuario Final',
)


# herramientas que el agente puede utilizar enlistados para que el modelo realmente realice las operaciones de base de datos
#basicamente todas las funciones que el agente puede realizar en la base de datos de LUNARA y se presentan mas debajo
ADMIN_DATABASE_TOOLS = [
    {
        #definicion listar tablas de la bd
        'type': 'function',
        'function': {
            'name': 'list_database_tables',
            'description': 'Lista las tablas de negocio disponibles en la base de datos de LUNARA.',
            'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
        },
    },
    {
        #definicion leer registros de la bd (dependiendo los filtros que pida el administrador)
        'type': 'function',
        'function': {
            'name': 'read_records',
            'description': 'Consulta hasta 100 registros por página. Usa filtros exactos opcionales y nunca solicites credenciales.',
            'parameters': {
                'type': 'object',
                #propiedades por defecto para que el modelo pueda realizar la consulta de registros
                'properties': {
                    'table': {'type': 'string', 'enum': sorted(ADMIN_TABLES)},
                    'filters': {'type': 'object', 'additionalProperties': True},
                    'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100},
                    'offset': {'type': 'integer', 'minimum': 0},
                },
                'required': ['table'],
                'additionalProperties': False,
            },
        },
    },
    {
        #definicion describir campos para crear un registro en la bd
        'type': 'function',
        'function': {
            'name': 'describe_create_fields',
            'description': 'Consulta los campos reales, tipos y campos obligatorios para crear un registro en una tabla.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'table': {'type': 'string', 'enum': sorted(ADMIN_TABLES)},
                },
                'required': ['table'],
                'additionalProperties': False,
            },
        },
    },
    {
        #definicion crear un registro en la bd
        'type': 'function',
        'function': {
            'name': 'create_record',
            'description': 'Crea un registro usando nombres de columna exactos. Consulta describe_create_fields primero y no inventes datos faltantes.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'table': {'type': 'string', 'enum': sorted(ADMIN_TABLES)},
                    'values': {'type': 'object', 'additionalProperties': True},
                },
                'required': ['table', 'values'],
                'additionalProperties': False,
            },
        },
    },
    {
        #definicion actualizar un registro en la bd
        'type': 'function',
        'function': {
            'name': 'update_record',
            'description': 'Actualiza un registro. Incluye siempre filters.id para limitar el cambio a una fila.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'table': {'type': 'string', 'enum': sorted(ADMIN_TABLES)},
                    'filters': {'type': 'object', 'additionalProperties': True},
                    'values': {'type': 'object', 'additionalProperties': True},
                    'change_password': {'type': 'boolean'},
                },
                'required': ['table', 'filters', 'values'],
                'additionalProperties': False,
            },
        },
    },
    {
        #definicion eliminar un registro en la bd
        'type': 'function',
        'function': {
            'name': 'delete_record',
            'description': 'Elimina registros. Si son menos de 5, procede directamente. Si son 5 o más, exige Destructive Password.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'table': {'type': 'string', 'enum': sorted(ADMIN_TABLES)},
                    'filters': {'type': 'object', 'additionalProperties': True},
                    'ids': {
                        'type': 'array',
                        'items': {'type': 'integer'},
                        'description': 'Lista de IDs para eliminar múltiples registros en una sola operación.'
                    },
                },
                'required': ['table'],
                'additionalProperties': False,
            },
        },
    },
]


# TODAS LAS FUNCIONES QUE EL AGENTE PUEDE REALIZAR Y USAR

# valida si el nombre de la columna se menciona y contiene palabras que indiquen que es un dato sensible
#para negarlo enseguida
def _is_sensitive_column(column_name: str) -> bool:
    """Indica si el nombre de una columna coincide con marcadores de datos privados."""
    normalized = column_name.lower()
    return any(marker in normalized for marker in SENSITIVE_COLUMN_MARKERS)

#esto identifica el nombre de la columna y lo reescribe correctamente
#para que no existan errores en sql y se pueda ejecutar correctamente
def _quote_identifier(identifier: str) -> str:
    """Escapa un identificador MySQL (tabla o columna) y lo delimita con backticks."""
    return '`' + identifier.replace('`', '``') + '`'

#Describe los requisitos para crear un registro nuevo
#y los pide si so campos required y no se han proporcionado

def _describe_create_fields(
    column_rows: list[dict],
    role_values: list[str] | None = None,
) -> dict:
    """Convierte la descripción de columnas MySQL en metadatos para el formulario de alta.

    Omite IDs autoincrementales y campos sensibles; devuelve tipo, obligatoriedad y,
    cuando existe, la lista de valores permitidos de un ENUM o de un rol.
    """
    # 
    fields = []#es la lista de campos que se va mostrar en json para que el agente pueda crear un registro nuevo
    required_fields = []#es la lista de campos que son obligatorios para crear un registro nuevo
    secure_password_required = False#NO PIDE LA CONTRASENA porque se maneja en un campo aparte

    #mysql manda las columnas de la tabla en un diccionario con sus propiedades y asi poder armar el formulario de alta de registro
    for row in column_rows:
        name = row.get('Field') or row.get('field')
        # toma el nombre en minusculas para que no haya confusion
        if not name or name.lower() == 'id' or 'auto_increment' in str(row.get('Extra') or '').lower():
            continue
        is_password = name.lower() == 'password'

        # ponemos en obligatorio los campos que no permiten nulos y no tienen valor por defecto
        required = (
            str(row.get('Null', row.get('null', 'YES'))).upper() == 'NO'
            and row.get('Default', row.get('default')) is None
        )
        #nombre de rol es obligatorio para crear un usuario nuevo
        if name.lower() in {'role', 'role_id'}:
            required = True
        #si es password no lo mostramos en el formulario y lo pedimos en un campo seguro aparte
        if is_password:
            secure_password_required = required
            continue
        #si es un campo sensible no lo mostramos en el formulario y no lo pedimos
        if _is_sensitive_column(name):
            continue
        # Guardamos nombre tipo y obligatoriedad para que el formulario se arme con datos reales
        field = {
            'name': name,
            'type': row.get('Type') or row.get('type') or 'unknown',
            'required': required,
        }
       # Convierte el tipo de dato a texto para analizarlo
        type_description = str(field['type'])
        # Busca mediante expresiones regulares si la columna solo acepta una lista fija de opciones (ENUM)
        enum_match = re.fullmatch(r"enum\((.*)\)", type_description, re.IGNORECASE)


        if enum_match:
            # Un campo ENUM solo puede tomar las opciones definidas en MySQL
            field['allowed_values'] = re.findall(r"'((?:[^']|'')*)'", enum_match.group(1))
        elif name.lower() == 'role' and role_values:
            field['allowed_values'] = role_values
        fields.append(field)
        if required:
            required_fields.append(name)
    return {
        'fields': fields,
        'required_fields': required_fields,
        'secure_password_required': secure_password_required,
    }

#obtiene los roles de los usuarios disponibles
def _get_user_role_values(cursor, table: str, column_names: set[str]) -> list[str]:
    """Obtiene los roles ya usados en la tabla o usa las opciones predeterminadas de LUNARA."""
    role_column = next(
        (name for name in column_names if name and name.lower() == 'role'),
        None,
    )
    if not role_column:
        return []
    # Toma los roles de las cuentas existentes para que el nuevo staff use un nombre reconocido
    cursor.execute(
        f'SELECT DISTINCT {_quote_identifier(role_column)} '
        f'FROM {_quote_identifier(table)} WHERE {_quote_identifier(role_column)} IS NOT NULL '
        f"AND TRIM(CAST({_quote_identifier(role_column)} AS CHAR)) <> '' "
        f'ORDER BY {_quote_identifier(role_column)}'
    )
    values = [
        str(next(iter(row.values())))
        for row in cursor.fetchall()
        if row and next(iter(row.values())) is not None
    ]
    # Una base nueva todavia no tiene roles guardados; en ese caso mostramos los roles de LUNARA
    return values or list(SUPPORTED_USER_ROLES)

#rechaza valores que no correspondan a las columnas
def _validate_record_values(values: dict, columns: set[str], *, allow_id: bool = False) -> bool:
    """Valida que los valores sean escalares y correspondan a columnas permitidas.

    Rechaza columnas sensibles y, salvo que el llamador lo permita explícitamente, también
    rechaza el campo id para impedir que se sobrescriba el identificador del registro.
    """
    # Rechaza datos que no correspondan a una columna real o que puedan exponer credenciales
    if not isinstance(values, dict):
        return False
    for key, value in values.items():
        if (
            key not in columns
            or _is_sensitive_column(key)
            or (key.lower() == 'id' and not allow_id)
            or not (value is None or isinstance(value, (str, int, float, bool)))
        ):
            return False
    return True

# Detecta si la pregunta del usuario requiere consultar o modificar la base de datos
def _is_admin_database_request(prompt: str) -> bool:
    """Usa palabras clave para decidir si una solicitud del administrador trata sobre datos."""
    return bool(re.search(
        #con palabras clave en espanol 
        r'\b(base de datos|tabla|registro|registros|cliente|clientes|usuario|usuarios|'
        r'membres[ií]a|plan|contrato|suscripci[oó]n|pago|pagos|'
        r'consulta|consultar|muestra|mostrar|lista|listar|cu[aá]nt[oa]s?|total|'
        r'crea|crear|agrega|agregar|inserta|insertar|actualiza|actualizar|'
        r'modifica|modificar|cambia|cambiar|elimina|eliminar|borra|borrar)\b',
        prompt,
        re.IGNORECASE,
    ))

#detecta si la pregunta del usuario es sobre una columna y la traduce a una tabla permitida
def detect_admin_records_table_request(prompt: str) -> str | None:
    """Reconoce solicitudes de lista y traduce alias en español/inglés a una tabla permitida."""
    normalized = (prompt or '').strip().lower()
    wants_list = re.search(
        r'\b(lista|listado|listar|muestra|mu[eé]strame|muestre|mostrar|ens[eé]ñame|dame|ver|consulta|consultar|registros?|datos)\b',
        normalized,
    )
    if not wants_list:
        return None

    table_aliases = {
        'client': r'\b(client|clientes?|miembros?)\b',
        'membership': r'\b(membership|membres[ií]as?|planes?)\b',
        'contract': r'\b(contract|contratos?|suscripciones?)\b',
        'payment': r'\b(payment|pagos?|cobros?)\b',
        'user': r'\b(user|usuarios?|staff|personal|empleados?)\b',
    }
    for table, pattern in table_aliases.items():
        if re.search(pattern, normalized):
            return table
    return None

# detecta si la pregunta del usuario es sobre una lista de clientes
def is_complete_client_list_request(prompt: str) -> bool:
    """Indica si la solicitud se detectó como una consulta de lista de clientes."""
    return detect_admin_records_table_request(prompt) == 'client'

# detecta si la pregunta es de listar una tabla y si el usuario tiene permisos de administrador
def get_admin_records_page(
    table: str,
    user_context: dict | None = None,
    page: int = 1,
) -> dict:
    """Devuelve una página de hasta 100 filas para la tabla solicitada por el administrador.

    Comprueba autorización, tabla permitida y oculta columnas sensibles antes de devolver
    registros y metadatos de paginación a la vista Flask.
    """
    context = user_context or {}
    if (
        normalize_role(context.get('role')) != 'administrador'
        or not context.get('agent_database_authorized')
    ):
        raise PermissionError('Se requiere autorización de Administrador para consultar registros.')
    #niega acceso
    if table not in ADMIN_TABLES:
        raise ValueError('La tabla solicitada no está permitida.')
    #y lo renderiza a una pagina de los registros de la tabla solicitada
    page_size = 100
    page = max(int(page), 1)
    offset = (page - 1) * page_size
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(f'SHOW COLUMNS FROM {_quote_identifier(table)}')
        columns = [
            row.get('Field') or row.get('field')
            for row in cursor.fetchall()
            if (row.get('Field') or row.get('field'))
            and not _is_sensitive_column(row.get('Field') or row.get('field'))
        ]
        projection = ', '.join(_quote_identifier(column) for column in columns)
        cursor.execute(f'SELECT COUNT(*) AS total FROM {_quote_identifier(table)}')
        total = int(cursor.fetchone()['total'])
        cursor.execute(
            f'SELECT {projection} FROM {_quote_identifier(table)} ORDER BY `id` LIMIT %s OFFSET %s',
            (page_size, offset),
        )
        records = cursor.fetchall()
        return {
            'table': table,
            'records': records,
            'columns': columns,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': max((total + page_size - 1) // page_size, 1),
        }
    finally:
        cursor.close()
        connection.close()

#paginacion de la lista de clientes para el administrador
def get_admin_client_page(user_context: dict | None = None, page: int = 1) -> dict:
    """Compatibilidad para obtener una pagina de clientes usando el paginador común."""
    return get_admin_records_page('client', user_context, page)

# Ejecuta herramientas de administracion (leer crear actualizar borrar) sobre MySQL
def execute_admin_database_tool(
    tool_name: str,
    arguments: dict,
    user_context: dict | None = None,
    secure_value: str | None = None,
) -> str:
    """Valida y ejecuta una herramienta de administración contra MySQL.

    La autorización y el esquema se comprueban en el servidor aunque Groq haya recibido
    una definición de herramienta. Los valores SQL se envían como parámetros; las altas,
    actualizaciones y borrados confirman la transacción solo después de ejecutarse.
    """
    # Si no hay contexto se usa un diccionario vacio
    context = user_context or {}
    # Estas herramientas solo estan disponibles para el administrador y despues de desbloquear el chat
    # Rechaza a quien no sea administrador
    if normalize_role(context.get('role')) != 'administrador':
        return 'Operación rechazada: solo el Administrador puede usar estas herramientas.'
    # Rechaza si no se desbloqueo el acceso a la base de datos
    if not context.get('agent_database_authorized'):
        return 'Operación rechazada: primero desbloquea las operaciones de base de datos.'
    # Los argumentos deben ser un diccionario
    if not isinstance(arguments, dict):
        return 'Operación rechazada: los argumentos no son válidos.'

    # Abre la conexion y un cursor que devuelve filas como diccionarios
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    try:
        # Aunque el modelo pida una tabla aqui confirmamos que exista y este permitida
        # Obtiene las tablas reales de la base de datos
        cursor.execute('SHOW TABLES')
        existing_tables = {next(iter(row.values())) for row in cursor.fetchall()}
        # Interseccion: tablas permitidas que ademas existen
        available_tables = ADMIN_TABLES & existing_tables

        # Herramienta: listar tablas y sus columnas
        if tool_name == 'list_database_tables':
            # Devuelve solo las tablas permitidas y sus columnas no sensibles
            schema = {}
            for available_table in sorted(available_tables):
                # Consulta las columnas de cada tabla
                cursor.execute(f'SHOW COLUMNS FROM {_quote_identifier(available_table)}')
                # Guarda solo los nombres de columnas no sensibles ordenados
                schema[available_table] = sorted(
                    (row.get('Field') or row.get('field'))
                    for row in cursor.fetchall()
                    if (row.get('Field') or row.get('field'))
                    and not _is_sensitive_column(row.get('Field') or row.get('field'))
                )
            return json.dumps(schema, ensure_ascii=False)

        # Para el resto de herramientas se necesita una tabla valida
        table = arguments.get('table')
        if not isinstance(table, str) or table not in available_tables:
            return 'Operación rechazada: la tabla no está disponible para administración.'

        # Lee la estructura de la tabla elegida
        cursor.execute(f'SHOW COLUMNS FROM {_quote_identifier(table)}')
        column_rows = cursor.fetchall()
        # Separamos nombres visibles de credenciales para no mostrar contrasenas en consultas o formularios
        # Todos los nombres de columna
        column_names = {row.get('Field') or row.get('field') for row in column_rows}
        # Solo las columnas que se pueden mostrar
        visible_columns = sorted(name for name in column_names if name and not _is_sensitive_column(name))
        # Nombre de tabla escapado para usarlo en SQL
        quoted_table = _quote_identifier(table)

        # Herramienta: describir los campos para crear un registro
        if tool_name == 'describe_create_fields':
            # La interfaz utiliza estos metadatos para pedir valores reales y obligatorios
            # El agente consulta el esquema antes de preguntar que informacion hace falta
            # Para la tabla user obtiene los roles validos
            role_values = (
                _get_user_role_values(cursor, table, column_names)
                if table == 'user'
                else []
            )
            return json.dumps({
                'table': table,
                **_describe_create_fields(column_rows, role_values),
            }, ensure_ascii=False)

        # Herramienta: leer registros
        if tool_name == 'read_records':
            # Los filtros limites y desplazamientos se validan antes de armar la consulta
            filters = arguments.get('filters') or {}
            # Solo se consulta con filtros validos y valores enviados por parametros
            if not isinstance(filters, dict) or not _validate_record_values(filters, column_names, allow_id=True):
                return 'Operación rechazada: los filtros contienen campos o valores no permitidos.'
            # Construye el WHERE con marcadores %s
            where_parts = []
            parameters = []
            for key, value in filters.items():
                quoted_column = _quote_identifier(key)
                # NULL se compara con IS NULL
                if value is None:
                    where_parts.append(f'{quoted_column} IS NULL')
                else:
                    where_parts.append(f'{quoted_column} = %s')
                    parameters.append(value)
            where_sql = ' WHERE ' + ' AND '.join(where_parts) if where_parts else ''
            # Limite: entero entre 1 y 100 (por defecto 100)
            limit = arguments.get('limit', 100)
            if not isinstance(limit, int) or isinstance(limit, bool):
                limit = 100
            limit = min(max(limit, 1), 100)
            # Desplazamiento: entero mayor o igual a 0
            offset = arguments.get('offset', 0)
            if not isinstance(offset, int) or isinstance(offset, bool):
                offset = 0
            offset = max(offset, 0)
            # Solo se seleccionan columnas visibles
            projection = ', '.join(_quote_identifier(name) for name in visible_columns)
            cursor.execute(
                f'SELECT {projection} FROM {quoted_table}{where_sql} LIMIT %s OFFSET %s',
                (*parameters, limit, offset),
            )
            return json.dumps(cursor.fetchall(), ensure_ascii=False, default=str)

        # Herramientas: crear o actualizar registros
        if tool_name in {'create_record', 'update_record'}:
            # La misma rama procesa altas y cambios; el alta ademas verifica campos obligatorios
            values = arguments.get('values') or {}
            # Para crear prepara el esquema que se usara para revisar y mostrar el formulario

            # Roles validos solo al crear un usuario
            role_values = (
                _get_user_role_values(cursor, table, column_names)
                if tool_name == 'create_record' and table == 'user'
                else []
            )
            # Esquema del formulario solo al crear
            schema = (
                _describe_create_fields(column_rows, role_values)
                if tool_name == 'create_record'
                else None
            )
            # Si los valores no son un diccionario devuelve el formulario
            if tool_name == 'create_record' and not isinstance(values, dict):
                return json.dumps({
                    'requires_input': True,
                    'table': table,
                    'invalid_fields': [],
                    **schema,
                }, ensure_ascii=False)
            if tool_name == 'create_record':
                # Verifica que el formulario reciba nombres de columnas reales y valores simples
                # No acepta nombres de campo inventados ni valores que el formulario no puede enviar
                # Campos invalidos: inexistentes sensibles "id" o con tipo no permitido
                invalid_fields = [
                    key for key, value in values.items()
                    if (
                        key not in column_names
                        or _is_sensitive_column(key)
                        or key.lower() == 'id'
                        or not (value is None or isinstance(value, (str, int, float, bool)))
                    )
                ]
                # Si hay invalidos vuelve a pedir datos
                if invalid_fields:
                    return json.dumps({
                        'requires_input': True,
                        'table': table,
                        'invalid_fields': invalid_fields,
                        **schema,
                    }, ensure_ascii=False)
            # Validacion general de los valores
            if not _validate_record_values(values, column_names):
                return 'Operación rechazada: los valores contienen campos o tipos no permitidos.'
            # Copia para poder modificarlo sin afectar el original
            values = dict(values)

            if tool_name == 'create_record':
                # El alta se detiene si el rol no existe o falta algun dato obligatorio
                # Busca el campo "role" en el esquema
                role_field = next(
                    (field for field in schema['fields'] if field['name'].lower() == 'role'),
                    None,
                )
                # Un rol desconocido vuelve al formulario para que se seleccione una opcion valida
                if (
                    role_field
                    and values.get(role_field['name']) not in (None, '')
                    and role_field.get('allowed_values')
                    and values[role_field['name']] not in role_field['allowed_values']
                ):
                    return json.dumps({
                        'requires_input': True,
                        'table': table,
                        'invalid_fields': [role_field['name']],
                        **schema,
                    }, ensure_ascii=False)
                # Campos obligatorios que no vienen o estan vacios
                missing_fields = [
                    name for name in schema['required_fields']
                    if name not in values or values[name] is None or values[name] == ''
                ]
                if missing_fields:
                    # Devuelve que falta; todavia no se inserta nada en la base de datos
                    return json.dumps({
                        'requires_input': True,
                        'table': table,
                        'missing_fields': missing_fields,
                        **schema,
                    }, ensure_ascii=False)
                if table == 'user':
                    # La contrasena se recibe por el campo privado de la interfaz no por el chat
                    # Sin contrasena segura pide el recuadro privado
                    if not secure_value:
                        return json.dumps({
                            'requires_secure_value': True,
                            'message': 'Para crear el usuario, ingresa su contraseña en el recuadro seguro separado.',
                        }, ensure_ascii=False)
                    values['password'] = secure_value
                # Busca la definicion de la columna password
                password_column = next(
                    (row for row in column_rows if (row.get('Field') or row.get('field')) == 'password'),
                    None,
                )
                # Si password es obligatoria sin valor por defecto y esta vacia la pide
                if (
                    table == 'user'
                    and password_column
                    and password_column.get('Null') == 'NO'
                    and password_column.get('Default') is None
                    and not values.get('password')
                ):
                    return json.dumps({
                        'requires_secure_value': True,
                        'message': 'Para crear el usuario, ingresa su contraseña en el recuadro seguro separado.',
                    }, ensure_ascii=False)
                # No se inserta un registro vacio
                if not values:
                    return 'Operación rechazada: indica los datos del registro.'
                # Arma el INSERT con columnas y marcadores
                names = list(values)
                columns_sql = ', '.join(_quote_identifier(name) for name in names)
                placeholders = ', '.join(['%s'] * len(names))
                # MySQL recibe los datos por separado de la consulta sin pegarlos al SQL
                cursor.execute(
                    f'INSERT INTO {quoted_table} ({columns_sql}) VALUES ({placeholders})',
                    tuple(values[name] for name in names),
                )
                # Confirma la transaccion y devuelve el id creado
                conexion.commit()
                return json.dumps({'created': True, 'id': cursor.lastrowid}, ensure_ascii=False)

            # A partir de aqui: actualizacion
            filters = arguments.get('filters') or {}
            # Campos que el administrador no puede cambiarse a si mismo
            protected_admin_fields = {
                'role', 'can_access_agent', 'view_contracts', 'view_financials',
                'manage_users', 'manage_plans', 'manage_contracts',
                'reset_passwords', 'view_own_profile',
            }
            # Los cambios deben senalar un ID y no pueden quitar al administrador sus propios permisos
            if (
                not isinstance(filters, dict)
                or 'id' not in filters
                or not _validate_record_values(filters, column_names, allow_id=True)
                or (
                    table == 'user'
                    and str(filters['id']) == str(context.get('user_id'))
                    and protected_admin_fields.intersection(values)
                )
            ):
                return 'Operación rechazada: usa un id válido; no puedes cambiar tu propio rol ni tus permisos.'
            if table == 'user' and arguments.get('change_password'):
                # Un cambio de contrasena toma su valor del formulario privado no de la conversacion
                if not secure_value:
                    return json.dumps({
                        'requires_secure_value': True,
                        'message': 'Para cambiar la contraseña, ingrésala en el recuadro seguro separado.',
                    }, ensure_ascii=False)
                values['password'] = secure_value
            # Debe haber al menos un campo a actualizar
            if not values:
                return 'Operación rechazada: indica al menos un campo para actualizar.'
            # Arma el UPDATE con parametros
            set_sql = ', '.join(f'{_quote_identifier(name)} = %s' for name in values)
            where_sql = ' AND '.join(f'{_quote_identifier(name)} = %s' for name in filters)
            cursor.execute(
                f'UPDATE {quoted_table} SET {set_sql} WHERE {where_sql}',
                (*values.values(), *filters.values()),
            )
            # Guarda cuantas filas cambiaron y confirma
            affected = cursor.rowcount
            conexion.commit()
            return json.dumps({'updated': affected}, ensure_ascii=False)

        # Herramienta: borrar registros
        if tool_name == 'delete_record':
            # La herramienta solicita confirmacion segun el tamano del borrado antes de ejecutar SQL
            ids_to_delete = arguments.get('ids') or []
            filters = arguments.get('filters') or {}

            # Cantidad de registros a borrar (1 si no es una lista de IDs)
            target_count = len(ids_to_delete) if isinstance(ids_to_delete, list) and ids_to_delete else 1

            # Cinco o mas IDs requieren que Flask gestione la confirmacion destructiva
            if target_count >= 5:
                # Si no hay confirmacion con contrasena pide confirmar
                if not context.get('destructive_password_confirmed'):
                    return json.dumps({
                        'allowed': False,
                        'requires_confirmation': True,
                        'confirmation_type': 'destructive',
                        'target_table': table,
                        'reason': f'Se requiere confirmación con Destructive Password para eliminar {target_count} registros de la tabla {table}.'
                    }, ensure_ascii=False)

            if isinstance(ids_to_delete, list) and ids_to_delete:
                # Si son IDs concretos el borrado se limita exactamente a esa lista
                # Todos los IDs deben ser enteros
                if not all(isinstance(i, int) for i in ids_to_delete):
                    return 'Operación rechazada: La lista de IDs debe contener números enteros.'
                
                # No permite borrar la propia cuenta
                if table == 'user' and any(str(i) == str(context.get('user_id')) for i in ids_to_delete):
                    return 'Operación rechazada: No puedes eliminar tu propia cuenta.'

                # DELETE con lista de IDs mediante marcadores
                placeholders = ', '.join(['%s'] * len(ids_to_delete))
                cursor.execute(
                    f'DELETE FROM {quoted_table} WHERE `id` IN ({placeholders})',
                    tuple(ids_to_delete),
                )
                affected = cursor.rowcount
                conexion.commit()
                return json.dumps({'deleted': affected}, ensure_ascii=False)

            # El borrado por filtro tambien exige un ID exacto y prohibe eliminar la propia cuenta
            if (
                not isinstance(filters, dict)
                or 'id' not in filters
                or not _validate_record_values(filters, column_names, allow_id=True)
                or (table == 'user' and str(filters['id']) == str(context.get('user_id')))
            ):
                return 'Operación rechazada: el borrado requiere un id válido y no puede eliminar tu propia cuenta.'

            # DELETE por filtros con parametros
            where_sql = ' AND '.join(f'{_quote_identifier(name)} = %s' for name in filters)
            cursor.execute(
                f'DELETE FROM {quoted_table} WHERE {where_sql}',
                tuple(filters.values()),
            )
            affected = cursor.rowcount
            conexion.commit()
            return json.dumps({'deleted': affected}, ensure_ascii=False)

        # Si no coincide ninguna herramienta
        return 'Operación rechazada: herramienta desconocida.'
    # Ante cualquier error deshace los cambios y devuelve un mensaje generico
    except Exception as exc:  # pragma: no cover
        conexion.rollback()
        return f'La base de datos rechazó la operación ({type(exc).__name__}).'
    # Siempre cierra cursor y conexion
    finally:
        cursor.close()
        conexion.close()


# Reglas de perfil alcance y autorizacion 
# Detecta si el mensaje pide una recomendacion musical
def is_music_recommendation_request(prompt: str) -> bool:
    """Aplica un filtro sencillo de palabras clave para solicitudes musicales de clientes."""
    # Normaliza el texto a minusculas sin espacios sobrantes
    normalized = (prompt or '').strip().lower()
    if not normalized:
        return False
    # ¿Menciona artista o cancion?
    mentions_artist_or_song = any(
        term in normalized
        for term in ('artista', 'artistas', 'cancion', 'canciones', 'song', 'songs', 'artist', 'artists')
    )
    # ¿Pide una recomendacion o habla de musica?
    requests_recommendation = any(
        term in normalized
        for term in ('recomiend', 'recomienda', 'favorito', 'gusto', 'musica', 'musical')
    )
    # Deben cumplirse ambas condiciones
    return mentions_artist_or_song and requests_recommendation


# Define a que tablas puede acceder el usuario segun su perfil
def get_data_access_scope(user_context: dict | None = None) -> dict:
    """Resume el perfil y las tablas asociadas a los permisos incluidos en el contexto."""
    context = user_context or {}
    role = normalize_role(context.get('role'))
    is_admin = role == 'administrador'
    allowed_tables = set()

    # El administrador tiene acceso total
    if is_admin:
        return {
            'full_access': True,
            'allowed_tables': {'user', 'client', 'membership', 'contract', 'payment'},
            'profile_type': 'administrador',
        }

    # Cada permiso habilita ciertas tablas
    if context.get('manage_users'):
        allowed_tables.add('user')
    if context.get('view_contracts') or context.get('manage_contracts'):
        allowed_tables.update({'client', 'contract', 'membership'})
    if context.get('manage_plans'):
        allowed_tables.add('membership')
    if context.get('view_financials'):
        allowed_tables.update({'payment', 'contract'})

    # Cliente o empleado segun el rol
    profile_type = 'cliente' if role in {'usuario final', 'cliente'} else 'empleado'
    return {
        'full_access': False,
        'allowed_tables': allowed_tables,
        'profile_type': profile_type,
    }


# Unifica el nombre del rol administrador
def normalize_role(role: str | None) -> str:
    """Unifica las variantes del rol administrador para autorización y presentación."""
    # Minusculas y sin espacios
    normalized = str(role or '').strip().casefold()
    # "admin" se trata como "administrador"
    if normalized in {'administrador', 'admin'}:
        return 'administrador'
    return normalized


# Revisa si la consulta es de solo lectura
def _is_read_only_operation(query: str) -> bool:
    """Reconoce por la primera palabra consultas que comienzan con SELECT o WITH."""
    # Extrae la primera palabra
    first_word = re.match(r'\s*([A-Za-z]+)', query)
    return bool(first_word and first_word.group(1).upper() in {'SELECT', 'WITH'})


# Limita al cliente a consultar solo sus propios datos
def validate_client_query_scope(query: str, user_context: dict | None = None) -> bool:
    """Para perfiles de cliente, exige una consulta de lectura con su propio id_usuario."""
    context = user_context or {}
    # Si no es cliente no aplica la restriccion
    if normalize_role(context.get('role')) not in {'cliente', 'usuario final'}:
        return True

    # Requiere id de usuario y consulta de lectura
    user_id = context.get('user_id')
    if user_id is None or not _is_read_only_operation(query):
        return False

    # La consulta debe contener WHERE id_usuario = <su id>
    pattern = rf"\bWHERE\s+id_usuario\s*=\s*{re.escape(str(user_id))}\b"
    return bool(re.search(pattern, query, re.IGNORECASE))


# Valida la contrasena maestra para operaciones sensibles
def require_admin_confirmation(
    operation: str,
    user_context: dict | None = None,
    supplied_password: str | None = None,
    master_password: str | None = None,
) -> dict:
    """Comprueba el rol administrador y compara la contraseña maestra de forma segura."""
    context = user_context or {}
    role = normalize_role(context.get('role'))
    # Solo el administrador puede continuar
    if role != 'administrador':
        return {
            'allowed': False,
            'requires_confirmation': True,
            'reason': 'Solo un administrador puede ejecutar esta operacion.',
        }
    # Faltan contrasenas
    if not supplied_password or not master_password:
        return {
            'allowed': False,
            'requires_confirmation': True,
            'reason': 'Se requiere una contraseña de confirmacion de administrador.',
        }
    # Comparacion segura contra ataques de tiempo
    if not secrets.compare_digest(supplied_password, master_password):
        return {
            'allowed': False,
            'requires_confirmation': True,
            'reason': 'La contraseña de confirmacion no es valida.',
        }
    # Contrasena correcta
    return {
        'allowed': True,
        'requires_confirmation': False,
        'reason': 'Confirmacion de administrador validada.',
    }


# Decide si una consulta SQL directa esta permitida segun el rol
def authorize_database_operation(query: str, user_context: dict | None = None) -> dict:
    """Aplica reglas por rol a una consulta SQL directa y explica si se autoriza o rechaza."""
    context = user_context or {}
    role = normalize_role(context.get('role'))
    clean = (query or '').strip()

    # Consulta vacia
    if not clean:
        return {'allowed': False, 'reason': 'La operacion de base de datos esta vacia.'}

    # Cliente: solo lectura y solo sus datos
    if role in {'cliente', 'usuario final'}:
        if not _is_read_only_operation(clean):
            return {
                'allowed': False,
                'reason': 'El cliente tiene solo lectura y puede consultar unicamente sus propios datos.',
            }
        if not validate_client_query_scope(clean, context):
            return {
                'allowed': False,
                'reason': 'El cliente solo puede consultar sus propios datos mediante WHERE id_usuario = ID_USUARIO.',
            }
        return {'allowed': True, 'reason': 'Cliente autorizado.'}

    # Gerente: solo lectura y sin datos sensibles
    if role in {'gerente', 'gestor de membresias'}:
        if not _is_read_only_operation(clean):
            return {'allowed': False, 'reason': 'El gerente solo puede ejecutar consultas de lectura.'}
        # Palabras sensibles prohibidas
        sensitive_terms = ('password', 'token', 'secret', 'credential', 'hash')
        if any(re.search(rf'\b{term}\b', clean, re.IGNORECASE) for term in sensitive_terms):
            return {'allowed': False, 'reason': 'La consulta contiene datos sensibles confenciales.'}
        return {'allowed': True, 'reason': 'Gerente autorizado para metricas consolidadas.'}

    # Administrador: las operaciones destructivas piden confirmacion
    if role == 'administrador':
        destructive_terms = (
            'DELETE', 'DROP', 'ALTER', 'TRUNCATE', 'UPDATE', 'INSERT',
            'REPLACE', 'GRANT', 'REVOKE', 'CALL', 'LOAD', 'OUTFILE', 'DUMPFILE',
        )
        if any(token in clean.upper() for token in destructive_terms):
            return {
                'allowed': False,
                'requires_confirmation': True,
                'reason': 'La operacion sensible requiere confirmacion de administrador.',
            }
        return {'allowed': True, 'reason': 'Administrador autorizado.'}

    # Cualquier otro rol queda sin permisos
    return {'allowed': False, 'reason': 'El rol no tiene permisos para ejecutar esta operacion.'}


# --- Instrucciones que adaptan la conversacion al perfil actual ---
# Crea el mensaje de sistema para el modelo segun el usuario
def build_agent_system_prompt(user_context: dict | None = None) -> str:
    """Construye el mensaje de sistema en español con las reglas propias del perfil LUNARA."""
    context = user_context or {}
    scope = get_data_access_scope(context)
    # Nombre y tipo de perfil del usuario
    name = str(context.get('name') or 'Usuario')
    profile_type = scope['profile_type']
    is_admin = normalize_role(context.get('role')) == 'administrador'

    if is_admin:
        # Las reglas cambian segun si el administrador ya desbloqueo o no las operaciones de datos
        role_instruction = (
            'Eres un asistente general y operativo para el Administrador de LUNARA. '
            'Responde preguntas generales y ayuda con la gestion del sistema. '
            + ('Cuando el administrador pregunte por registros o solicite cambios, usa las herramientas de base de datos disponibles. '
               if context.get('agent_database_authorized') else
               'Las herramientas de base de datos estan bloqueadas hasta que el administrador las desbloquee. ')
            + 'Solo realiza cambios cuando el usuario lo pida claramente. '
            'Para crear cualquier registro, consulta primero describe_create_fields con la tabla solicitada. '
            'Usa exclusivamente nombres de campo devueltos por esa herramienta y respeta sus tipos. '
            'Antes de crear, pide al usuario todos los campos obligatorios faltantes, explicando el tipo de dato esperado; no inventes datos ni supongas que un campo opcional es obligatorio. '
            'Al crear un registro en la tabla user, pregunta explícitamente qué rol desea asignar antes de llamar a create_record, aunque la base de datos indique que role tiene un valor predeterminado. Ofrece exactamente las opciones allowed_values devueltas por describe_create_fields y nunca elijas el rol por tu cuenta. '
            'Para crear un usuario, pide su contraseña únicamente mediante el recuadro seguro separado de la interfaz; nunca la incluyas en los mensajes ni en argumentos de herramientas. '
            'Si una herramienta requiere confirmación, informa al usuario que debe completar el panel de seguridad correspondiente. Nunca solicites contraseñas en el mensaje del chat.'
        )
    else:
        # Los demas perfiles solo reciben recomendaciones musicales
        role_instruction = (
            'Eres un asistente de recomendaciones musicales de LUNARA. '
            'Solo puede responder con recomendaciones musicales cuando el usuario mencione un artista o una cancion.'
        )

    # Instruccion comun para todos los perfiles
    common_instruction = (
        'Eres el asistente IA de LUNARA. Responde en español, con claridad y respeto. '
        'El usuario actual es ' + name + ' y su perfil es ' + profile_type + '. '
        + role_instruction
    )
    return common_instruction


# --- Utilidades de consulta SQL de solo lectura ---
# Ejecuta una consulta SELECT validada
def execute_sql_query(
    query: str,
    allowed_tables: set | None = None,
    user_context: dict | None = None,
) -> str:
    """Valida y ejecuta una consulta de lectura directa, con límites y restricciones SQL.

    Esta utilidad solo acepta SELECT/WITH, una sentencia, sin bloqueos ni columnas de
    contraseña, y devuelve como máximo 100 filas.
    """
    clean = (query or '').strip()
    if not clean:
        return 'La consulta esta vacia.'

    # Verifica permisos segun el rol
    authorization = authorize_database_operation(clean, user_context)
    if not authorization['allowed']:
        return f"Error de seguridad: {authorization['reason']}"
    if authorization.get('requires_confirmation'):
        return 'Error de seguridad: esta operacion requiere confirmacion de administrador.'

    # Solo se permiten SELECT o WITH
    first_word = re.match(r'[A-Za-z]+', clean)
    if not first_word or first_word.group(0).upper() not in {'SELECT', 'WITH'}:
        return 'Error de seguridad: solo se permiten consultas de lectura.'

    # Palabras que modifican datos o estructura
    forbidden = {
        'DELETE', 'UPDATE', 'DROP', 'INSERT', 'ALTER', 'CREATE', 'TRUNCATE',
        'REPLACE', 'GRANT', 'REVOKE', 'CALL', 'LOAD', 'OUTFILE', 'DUMPFILE',
    }
    # Bloquea la consulta si contiene alguna de ellas
    tokens = re.findall(r'[A-Za-z_]+', clean.upper())
    if any(token in forbidden for token in tokens):
        return 'Error de seguridad: la consulta contiene instrucciones no permitidas.'

    # Solo una sentencia (se ignora un ; final)
    single_statement = clean[:-1] if clean.endswith(';') else clean
    if ';' in single_statement:
        return 'Error de seguridad: solo se permite una consulta por solicitud.'

    # Sin bloqueos de filas
    if re.search(r'\bFOR\s+UPDATE\b|\bLOCK\s+IN\s+SHARE\s+MODE\b', clean, re.IGNORECASE):
        return 'Error de seguridad: no se permiten bloqueos de registros.'

    # No se permite consultar contrasenas
    if re.search(r'\bpassword\b', clean, re.IGNORECASE):
        return 'Error de seguridad: no se permite consultar credenciales.'

    # Revisa que la tabla consultada este permitida
    if allowed_tables is not None:
        table_match = re.search(r'\bFROM\s+`?([A-Za-z_][A-Za-z0-9_]*)`?', clean, re.IGNORECASE)
        if table_match and table_match.group(1).lower() not in allowed_tables:
            return f'Error de seguridad: no tienes permiso para consultar la tabla {table_match.group(1)}.'

    # Conexion a la base de datos
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    try:
        # Transaccion de solo lectura por seguridad
        cursor.execute('START TRANSACTION READ ONLY')
        cursor.execute(clean)
        # Maximo 100 filas
        rows = cursor.fetchmany(100)
        if not rows:
            return 'La consulta no devolvio resultados.'
        result = json.dumps(rows, ensure_ascii=False, indent=2, default=str)
        # Avisa si se alcanzo el limite
        if len(rows) == 100:
            result += '\nSe muestran como maximo 100 filas.'
        return result
    except Exception as exc:  # pragma: no cover
        return f'Error en la consulta SQL: {exc}'
    finally:
        # Siempre revierte y cierra la conexion
        conexion.rollback()
        cursor.close()
        conexion.close()


# Devuelve el esquema de la base de datos como texto
def get_database_schema() -> str:
    """Describe tablas y columnas de la base activa, omitiendo nombres de columnas sensibles."""
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    try:
        # Lee tablas y columnas desde information_schema
        cursor.execute(
            """
            SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name,
                   DATA_TYPE AS data_type, COLUMN_TYPE AS column_type,
                   IS_NULLABLE AS is_nullable
            FROM information_schema.columns
            WHERE TABLE_SCHEMA = DATABASE()
            ORDER BY TABLE_NAME, ORDINAL_POSITION
            """
        )
        rows = cursor.fetchall()
        if not rows:
            return 'No se encontro informacion del esquema de la base de datos.'

        # Agrupa columnas por tabla omitiendo las sensibles
        schema = {}
        for row in rows:
            column_name = row['column_name'].lower()
            if any(sensitive in column_name for sensitive in ('password', 'secret', 'token', 'hash')):
                continue
            table = row['table_name']
            schema.setdefault(table, []).append(
                f"{row['column_name']} ({row['data_type']}, {row['column_type']}, nullable={row['is_nullable']})"
            )

        # Convierte el esquema a texto legible
        partes = []
        for table, columns in schema.items():
            partes.append(f"Tabla: {table}")
            partes.append('  - ' + ', '.join(columns))
        return '\n'.join(partes)
    finally:
        cursor.close()
        conexion.close()


# Cuenta contratos totales activos e inactivos
def get_subscription_status_counts() -> str:
    """Cuenta contratos totales, activos e inactivos y devuelve el resultado como JSON."""
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    try:
        # Transaccion de solo lectura
        cursor.execute('START TRANSACTION READ ONLY')
        # status = 1 se considera activo
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END), 0) AS activas,
                COALESCE(SUM(CASE WHEN status <> 1 THEN 1 ELSE 0 END), 0) AS inactivas
            FROM contract
            """
        )
        row = cursor.fetchone()
        # Convierte todos los valores a enteros
        return json.dumps({key: int(value or 0) for key, value in row.items()})
    except Exception as exc:  # pragma: no cover
        return f'Error al contar suscripciones: {exc}'
    finally:
        conexion.rollback()
        cursor.close()
        conexion.close()


# Ciclo de llamadas entre Groq las herramientas locales y MySQL
# Gestiona la conversacion del administrador con el modelo y sus herramientas
def _generate_admin_tool_response(
    client,
    model: str,
    messages: list[dict],
    user_context: dict,
    secure_value: str | None,
) -> str | dict:
    """Completa la conversación administrativa atendiendo las llamadas a herramientas.

    Envía resultados de vuelta al modelo para que redacte la respuesta, pero detiene el
    ciclo cuando una acción necesita confirmación, datos de formulario o una clave segura.
    """
    # Cada iteracion permite que el modelo solicite otra herramienta usando el resultado anterior
    # Maximo 5 vueltas para evitar ciclos infinitos
    for _ in range(5):
        # Llama al modelo con las herramientas disponibles
        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=ADMIN_DATABASE_TOOLS,
            tool_choice='auto',
            temperature=0.2,
            max_completion_tokens=700,
        )
        message = completion.choices[0].message
        tool_calls = message.tool_calls or []
        # Sin herramientas: es la respuesta final
        if not tool_calls:
            return message.content or 'No pude generar una respuesta. Intenta de nuevo.'

        # Se conserva en el contexto de Groq que herramienta pidio y con que argumentos
        messages.append({
            'role': 'assistant',
            'content': message.content,
            'tool_calls': [
                {
                    'id': tool_call.id,
                    'type': 'function',
                    'function': {
                        'name': tool_call.function.name,
                        'arguments': tool_call.function.arguments,
                    },
                }
                for tool_call in tool_calls
            ],
        })
        # Procesa cada herramienta solicitada
        for tool_call in tool_calls:
            # Convierte los argumentos de texto JSON a diccionario
            try:
                arguments = json.loads(tool_call.function.arguments or '{}')
            except (TypeError, json.JSONDecodeError):
                result = 'Operación rechazada: argumentos inválidos.'
            else:
                # La clave viaja al ejecutor local nunca se agrega a los mensajes enviados a Groq
                # Ejecuta la herramienta en el servidor
                result = execute_admin_database_tool(
                    tool_call.function.name,
                    arguments,
                    user_context,
                    secure_value=secure_value,
                )
                
                # Intenta interpretar el resultado como JSON para detectar pasos especiales
                try:
                    parsed_result = json.loads(result)
                    # Caso: se requiere confirmacion
                    if isinstance(parsed_result, dict) and parsed_result.get('requires_confirmation'):
                        if (
                            tool_call.function.name == 'delete_record'
                            and isinstance(arguments.get('ids'), list)
                            and len(arguments['ids']) >= 5
                            and arguments.get('table') in ADMIN_TABLES
                        ):
                            # Guarda la misma tabla e IDs que pidio borrar; el formulario pedira confirmacion
                            return {
                                **parsed_result,
                                'pending_delete': {
                                    'tool_name': tool_call.function.name,
                                    'arguments': arguments,
                                },
                            }
                        # Otro tipo de confirmacion: no se ejecuto nada
                        reason = parsed_result.get('reason')
                        if isinstance(reason, str) and reason:
                            return (
                                f'No se pudo abrir el panel de seguridad. '
                                f'La operación no se ejecutó. {reason}'
                            )
                        return 'No se pudo abrir el panel de seguridad. La operación no se ejecutó.'
                    # Caso: faltan datos para crear un registro
                    if (
                        isinstance(parsed_result, dict)
                        and parsed_result.get('requires_input')
                        and tool_call.function.name == 'create_record'
                    ):
                        # Si falta informacion conserva solo datos permitidos para llenar el formulario
                        fields = parsed_result.get('fields') or []
                        # Nombres de campos validos del formulario
                        allowed_field_names = {
                            field.get('name')
                            for field in fields
                            if isinstance(field, dict) and isinstance(field.get('name'), str)
                        }
                        supplied_values = arguments.get('values')
                        # Filtra valores: solo campos permitidos y tipos simples
                        safe_values = {
                            name: value
                            for name, value in supplied_values.items()
                            if name in allowed_field_names
                            and (value is None or isinstance(value, (str, int, float, bool)))
                        } if isinstance(supplied_values, dict) else {}
                        return {
                            **parsed_result,
                            'pending_create': {
                                'tool_name': tool_call.function.name,
                                'arguments': {
                                    'table': arguments.get('table'),
                                    'values': safe_values,
                                },
                            },
                        }
                    # Caso: falta la contrasena segura
                    if isinstance(parsed_result, dict) and parsed_result.get('requires_secure_value'):
                        if tool_call.function.name == 'create_record':
                            # Cuando todos los datos estan listos menos la clave pide solo la clave en privado
                            # Obtiene el esquema para reconstruir el formulario
                            try:
                                schema = json.loads(execute_admin_database_tool(
                                    'describe_create_fields',
                                    {'table': arguments.get('table')},
                                    user_context,
                                ))
                            except (TypeError, ValueError):
                                schema = {}
                            if isinstance(schema, dict) and schema.get('fields'):
                                # Campos validos del esquema
                                allowed_field_names = {
                                    field.get('name')
                                    for field in schema['fields']
                                    if isinstance(field, dict) and isinstance(field.get('name'), str)
                                }
                                supplied_values = arguments.get('values')
                                # Conserva solo valores seguros
                                safe_values = {
                                    name: value
                                    for name, value in supplied_values.items()
                                    if name in allowed_field_names
                                    and (value is None or isinstance(value, (str, int, float, bool)))
                                } if isinstance(supplied_values, dict) else {}
                                return {
                                    **schema,
                                    'requires_input': True,
                                    'pending_create': {
                                        'tool_name': tool_call.function.name,
                                        'arguments': {
                                            'table': arguments.get('table'),
                                            'values': safe_values,
                                        },
                                    },
                                }
                        return parsed_result
                # Si el resultado no es JSON se sigue normalmente
                except (ValueError, TypeError):
                    pass

            # Devuelve el resultado de la herramienta al modelo
            messages.append({
                'role': 'tool',
                'tool_call_id': tool_call.id,
                'content': result,
            })

    # Se alcanzo el limite de 5 vueltas
    return 'La solicitud necesitó demasiadas operaciones encadenadas. Divide el cambio en pasos más pequeños.'


# Punto de entrada usado por Flask para cada mensaje del chat
# Funcion principal que genera la respuesta del agente
def generate_agent_response(
    prompt: str,
    user_context: dict | None = None,
    secure_value: str | None = None,
    conversation_history: list[dict] | None = None,
) -> str | dict:
    """Valida la solicitud, prepara contexto e invoca Groq para generar una respuesta.

    Los administradores autorizados reciben herramientas de base de datos; los demás
    perfiles quedan limitados a solicitudes de recomendación musical.
    """
    # Limpia el texto del usuario
    prompt = (prompt or '').strip()
    # Indica si el usuario es administrador
    is_admin = normalize_role((user_context or {}).get('role')) == 'administrador'
    # El envio de una contrasena puede llegar sin texto; se transforma en una instruccion interna segura
    if not prompt and is_admin and secure_value and (user_context or {}).get('agent_database_authorized'):
        prompt = 'La contraseña solicitada para la operación pendiente llegó en el campo seguro. Completa la operación.'
    if not prompt:
        return 'Escribe tu pregunta para consultar al agente.' if is_admin else 'Escribe una recomendacion musical para consultar al agente.'
    if not is_admin and not is_music_recommendation_request(prompt):
        return 'Solo puedo recomendar musica. Menciona un artista o cancion que quieras explorar.'
    if (
        is_admin
        and _is_admin_database_request(prompt)
        and not (user_context or {}).get('agent_database_authorized')
    ):
        # No se llama a la IA con herramientas de base de datos hasta que el administrador las desbloquee
        return 'Desbloquea las operaciones con tu Master Password en el panel lateral antes de consultar o modificar registros.'

    api_key = os.environ.get('GROQ_API_KEY')
    if not api_key:
        return 'Falta configurar GROQ_API_KEY en el archivo .env de Proyecto Final y reiniciar Flask.'
    if Groq is None:
        return 'Falta instalar el SDK de Groq. Ejecuta: py -m pip install groq python-dotenv'

    try:
        # El modelo configurable permite cambiar el servicio/modelo sin alterar el flujo Flask
        client = Groq(api_key=api_key)
        model = os.environ.get('GROQ_MODEL', 'openai/gpt-oss-120b').strip()
        prompt_context = dict(user_context or {})
        # Solo se informa a la IA que llego una clave; el valor real no se anade a sus mensajes
        prompt_context['secure_value_supplied'] = bool(is_admin and secure_value)
        system_prompt = build_agent_system_prompt(prompt_context)
        messages = [{'role': 'system', 'content': system_prompt}]
        if is_admin and conversation_history:
            # Conserva una ventana reciente de conversacion para aportar contexto sin crecer sin limite
            messages.extend(
                {'role': item['role'], 'content': item['content']}
                for item in conversation_history[-12:]
                if item.get('role') in {'user', 'assistant'}
                and isinstance(item.get('content'), str)
            )
        if not messages or messages[-1].get('role') != 'user' or messages[-1].get('content') != prompt:
            messages.append({'role': 'user', 'content': prompt})

        if is_admin and (user_context or {}).get('agent_database_authorized'):
            # Solo entra al ciclo de herramientas cuando el administrador ya desbloque los datos
            return _generate_admin_tool_response(
                client,
                model,
                messages,
                user_context or {},
                secure_value,
            )

        completion = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.2,
            max_completion_tokens=500,
        )
        fallback = 'No pude generar una respuesta. Intenta de nuevo.'
        return completion.choices[0].message.content or fallback
    except Exception as exc:
        error_text = str(exc)
        if 'tokens per minute' in error_text.lower() or 'tpm' in error_text.lower():
            return 'Groq alcanzo su limite temporal de tokens. Espera un momento y vuelve a enviar una pregunta breve.'
        return f'No pude conectar con Groq o consultar la base de datos: {error_text}'