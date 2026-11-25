from flask import Flask, render_template, request, redirect, url_for, flash, session
from db import get_connection
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from agent_ai import (
    detect_admin_records_table_request,
    execute_admin_database_tool,
    generate_agent_response,
    get_admin_records_page,
    normalize_role,
    require_admin_confirmation,
)

# inicializacion de la aplicacion flask
app = Flask(__name__)
# configuracion de la clave secreta para gestionar las sesiones de usuario
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# endpoints administrativos que requieren confirmacion especial para modificar datos
ADMIN_MUTATION_ENDPOINTS = {
    'staff_guardar', 'staff_actualizar', 'staff_eliminar',
    'clientes_guardar', 'clientes_actualizar', 'clientes_eliminar',
    'planes_guardar', 'planes_actualizar', 'planes_eliminar',
    'suscripciones_guardar', 'suscripciones_actualizar',
    'suscripciones_baja', 'suscripciones_eliminar',
    'pagos_guardar', 'pagos_actualizar', 'pagos_eliminar',
}
# rutas relacionadas con el agente ia y sus acciones
ADMIN_AGENT_ENDPOINTS = {'agente', 'agente_reset', 'agente_desbloquear', 'agente_bloquear'}
ADMIN_AGENT_ENDPOINTS.update({
    'agente_confirmar_borrado_tabla',
    'agente_confirmar_borrado_registros',
    'agente_cancelar_borrado_tabla',
    'agente_crear_registro',
    'agente_cancelar_creacion',
})
# tablas donde se permiten eliminaciones masivas con doble confirmacion
BULK_DELETE_TABLES = {'client', 'membership', 'contract', 'payment'}
BULK_DELETE_CONFIRMATION_WINDOW = 300
BULK_DELETE_LOCKOUT_SECONDS = 180
BULK_DELETE_LOCKOUT_TABLE = 'admin_bulk_delete_lockouts'


def _remove_internal_security_messages(history):
    """Oculta de la conversación las respuestas estructuradas internas de seguridad."""
    if not isinstance(history, list):
        return history

    visible_messages = []
    for message in history:
        if not isinstance(message, dict) or message.get('role') != 'assistant':
            visible_messages.append(message)
            continue

        content = message.get('content')
        if isinstance(content, str):
            try:
                parsed_content = json.loads(content)
            except (TypeError, ValueError):
                parsed_content = None
            if isinstance(parsed_content, dict) and (
                parsed_content.get('requires_confirmation')
                or parsed_content.get('requires_secure_value')
            ):
                continue

        visible_messages.append(message)

    return visible_messages


# crea la tabla auxiliar que recuerda cuando un usuario debe esperar antes de reintentar un borrado
def _ensure_bulk_delete_lockout_table(cursor):
    cursor.execute(
        f"""CREATE TABLE IF NOT EXISTS `{BULK_DELETE_LOCKOUT_TABLE}` (
            user_id INT PRIMARY KEY,
            locked_until_epoch BIGINT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB"""
    )


# consulta si el usuario tiene un bloqueo activo por error en clave destructiva
def get_bulk_delete_lockout(user_id):
    connection = None
    cursor = None
    try:
        # devuelve el fin del bloqueo y si se pudo consultar la base de datos
        connection = get_connection()
        cursor = connection.cursor()
        _ensure_bulk_delete_lockout_table(cursor)
        cursor.execute(
            f'SELECT locked_until_epoch FROM `{BULK_DELETE_LOCKOUT_TABLE}` WHERE user_id = %s',
            (user_id,),
        )
        row = cursor.fetchone()
        return (int(row[0]) if row else 0), True
    except Exception:
        app.logger.exception('Could not verify persistent bulk-delete lockout')
        return 0, False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# registra el bloqueo temporal de borrado masivo para un usuario
def set_bulk_delete_lockout(user_id, locked_until_epoch):
    connection = None
    cursor = None
    try:
        # guarda el bloqueo por usuario para que siga vigente aunque se reinicie flask
        connection = get_connection()
        cursor = connection.cursor()
        _ensure_bulk_delete_lockout_table(cursor)
        cursor.execute(
            f"""INSERT INTO `{BULK_DELETE_LOCKOUT_TABLE}` (user_id, locked_until_epoch)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE locked_until_epoch = VALUES(locked_until_epoch)""",
            (user_id, locked_until_epoch),
        )
        connection.commit()
        return True
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception('Could not persist bulk-delete lockout')
        return False
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# comprueba si la sesion actual posee un permiso especifico
def user_has(permission_name):
    if normalize_role(session.get('role')) == 'administrador':
        return True
    permissions = session.get('permissions', {})
    return bool(permissions.get(permission_name, False))


# valida si el rol del usuario le permite interactuar con el agente ia
def can_access_agent(permissions=None, role=None):
    normalized_role = normalize_role(role or (permissions or {}).get('role'))
    return normalized_role == 'administrador'


# detecta si el agente esta esperando el ingreso de una clave en el campo privado
def agent_is_waiting_for_secure_value(history):
    # sirve para reconocer conversaciones antiguas donde el asistente ya habia pedido una contrasena
    if not history or history[-1].get('role') != 'assistant':
        return False
    message = str(history[-1].get('content') or '').lower()
    asks_for_password = 'contraseña' in message or 'contrasena' in message
    references_secure_field = any(
        phrase in message
        for phrase in ('campo seguro', 'campo de contraseña', 'campo de contrasena')
    )
    return asks_for_password and references_secure_field


# analiza si la peticion del usuario solicita un borrado masivo de alguna tabla o la base entera
def classify_bulk_delete_request(prompt):
    # distingue "borrar todos los clientes" de una peticion para borrar un solo registro
    normalized = str(prompt or '').lower()
    destructive_action = re.search(
        r'\b(borra|borrar|borrad[oa]s?|elimina|eliminar|eliminaci[oó]n(?:es)?|'
        r'vac[ií]a|vaciar|limpia|limpiar|'
        r'delete|truncate|remove|erase|empty|wipe|drop)\b',
        normalized,
    )
    if not destructive_action:
        return None
    if re.search(r'\b(base|base de datos|database|todas las tablas)\b', normalized):
        return 'database'
    if not re.search(
        r'\b(todo|toda|todos|todas|completa|completo|entera|entero|'
        r'all|entire|everything|bulk|masiv[oa]s?|masivamente|'
        r'vac[ií]a|vaciar|truncate|empty|wipe)\b',
        normalized,
    ):
        return None

    table_aliases = {
        'user': r'\b(users?|usuarios?|staff|personal)\b',
        'client': r'\b(clients?|clientes?)\b',
        'membership': r'\b(memberships?|membres[ií]as?|planes?)\b',
        'contract': r'\b(contracts?|contratos?|suscripciones?)\b',
        'payment': r'\b(payments?|pagos?)\b',
    }
    for table, pattern in table_aliases.items():
        if re.search(pattern, normalized):
            return table
    return 'unknown'


# verifica permisos antes de dar acceso a una vista
def require_permission(permission_name, redirect_route='home', message='No tienes permisos para acceder a esta sección.'):
    if not user_has(permission_name):
        flash(message, 'error')
        return redirect(url_for(redirect_route))
    return None


# genera sugerencias rapidas de consulta para el chat del agente
def get_agent_quick_prompts(permissions):
    """Devuelve atajos adecuados al perfil que usa el agente."""
    if not can_access_agent(permissions):
        return []
    return [
        'Lista las tablas disponibles',
        'Muéstrame los clientes registrados',
        '¿Cuántos contratos están activos?',
        'Recomiéndame una canción de un artista que mencione',
    ]


# configura el panel visual y modulos visibles segun el rol del usuario
def get_role_view(permissions):
    """Selecciona la vista inicial y los módulos disponibles por perfil."""
    role = normalize_role(permissions.get('role') or 'Usuario')
    is_admin = role == 'administrador'
    can_agent = can_access_agent(permissions)

    if is_admin:
        role_label = 'Administrador'
        modules = [
            'staff', 'clientes', 'planes', 'suscripciones',
            'pagos', 'reporte', 'agente'
        ]
        show_full_dashboard = True
    elif role in {'usuario final', 'cliente'}:
        role_label = 'Cliente'
        modules = []
        show_full_dashboard = False
    else:
        role_label = 'Empleado'
        modules = []
        if permissions.get('manage_users'):
            modules.append('staff')
        if permissions.get('view_contracts') or permissions.get('manage_contracts'):
            modules.append('clientes')
        if permissions.get('manage_plans'):
            modules.append('planes')
        if permissions.get('view_contracts') or permissions.get('manage_contracts'):
            modules.append('suscripciones')
        if permissions.get('view_financials'):
            modules.extend(['pagos', 'reporte'])
        show_full_dashboard = False

    return {
        'role': role_label,
        'template': 'role_dashboard.html',
        'modules': modules,
        'show_full_dashboard': show_full_dashboard,
        'show_agent': can_agent,
    }


# filtro global de seguridad que valida la sesion y tokens csrf en cada peticion
@app.before_request
def verificar_sesion():
    if request.endpoint in ('login', 'logout', 'static'):
        return None

    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder al sistema.', 'error')
        return redirect(url_for('login'))

    if normalize_role(session.get('role')) == 'administrador':
        session['role'] = 'Administrador'
        permissions = dict(session.get('permissions', {}))
        permissions.update({
            'can_access_agent': True,
            'view_contracts': True,
            'view_financials': True,
            'manage_users': True,
            'manage_plans': True,
            'manage_contracts': True,
            'reset_passwords': True,
            'view_own_profile': True,
        })
        session['permissions'] = permissions

    route_permissions = {
        'staff_form': 'manage_users',
        'staff_guardar': 'manage_users',
        'staff_editar': 'manage_users',
        'staff_actualizar': 'manage_users',
        'staff_eliminar': 'manage_users',
        'clientes_form': 'view_contracts',
        'clientes_guardar': 'manage_contracts',
        'clientes_editar': 'manage_contracts',
        'clientes_actualizar': 'manage_contracts',
        'clientes_eliminar': 'manage_contracts',
        'planes_form': 'manage_plans',
        'planes_guardar': 'manage_plans',
        'planes_editar': 'manage_plans',
        'planes_actualizar': 'manage_plans',
        'planes_eliminar': 'manage_plans',
        'suscripciones_form': 'view_contracts',
        'suscripciones_guardar': 'manage_contracts',
        'suscripciones_editar': 'view_contracts',
        'suscripciones_actualizar': 'manage_contracts',
        'suscripciones_baja': 'manage_contracts',
        'suscripciones_eliminar': 'manage_contracts',
        'pagos_form': 'view_financials',
        'pagos_guardar': 'view_financials',
        'pagos_editar': 'view_financials',
        'pagos_actualizar': 'view_financials',
        'pagos_eliminar': 'view_financials',
        'reporte_auditoria_ingresos': 'view_financials',
    }

    if request.endpoint in ADMIN_AGENT_ENDPOINTS and not can_access_agent(
        session.get('permissions', {}),
        session.get('role', ''),
    ):
        flash('El agente musical solo está disponible para el Administrador.', 'error')
        return redirect(url_for('home'))

    if request.endpoint in ADMIN_AGENT_ENDPOINTS and request.method == 'POST':
        expected_token = session.get('agent_csrf_token', '')
        supplied_token = request.form.get('csrf_token', '')
        if not expected_token or not secrets.compare_digest(expected_token, supplied_token):
            flash('La solicitud del agente expiró. Recarga la página e inténtalo de nuevo.', 'error')
            return redirect(url_for('agente'))

    if request.endpoint in ADMIN_MUTATION_ENDPOINTS:
        role = normalize_role(session.get('role'))
        if role != 'administrador':
            flash('Las operaciones de base de datos solo están disponibles para el Administrador.', 'error')
            return redirect(url_for('home'))
        confirmation = require_admin_confirmation(
            request.endpoint,
            {'role': role, 'user_id': session.get('user_id')},
            request.form.get('master_password', '').strip(),
            os.environ.get('MASTER_PASSWORD', ''),
        )
        if not confirmation['allowed']:
            flash(confirmation['reason'], 'error')
            return redirect(url_for('home'))

    permiso = route_permissions.get(request.endpoint)
    if permiso and not user_has(permiso):
        flash('No tienes permisos para acceder a esta sección.', 'error')
        return redirect(url_for('home'))


# gestiona la autenticacion de usuarios e inicio de sesion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Ingresa usuario y contraseña.', 'error')
            return redirect(url_for('login'))

        conexion = get_connection()
        cursor = conexion.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT
                    id, username, name, lastname, role,
                    can_access_agent, view_contracts, view_financials,
                    manage_users, manage_plans, manage_contracts,
                    reset_passwords, view_own_profile, is_active
                FROM user
                WHERE username = %s AND password = %s AND is_active = 1
                LIMIT 1
                """,
                (username, password)
            )
            usuario = cursor.fetchone()

            if not usuario:
                flash('Usuario o contraseña incorrectos.', 'error')
                return redirect(url_for('login'))

            session.clear()
            session['user_id'] = usuario['id']
            session['username'] = usuario['username']
            session['role'] = (
                'Administrador'
                if normalize_role(usuario['role']) == 'administrador'
                else usuario['role']
            )
            session['nombre_completo'] = f"{usuario['name']} {usuario['lastname']}"
            session['permissions'] = {
                'can_access_agent': bool(usuario['can_access_agent']),
                'view_contracts': bool(usuario['view_contracts']),
                'view_financials': bool(usuario['view_financials']),
                'manage_users': bool(usuario['manage_users']),
                'manage_plans': bool(usuario['manage_plans']),
                'manage_contracts': bool(usuario['manage_contracts']),
                'reset_passwords': bool(usuario['reset_passwords']),
                'view_own_profile': bool(usuario['view_own_profile'])
            }
            flash('Bienvenido a LUNARA.', 'success')
            return redirect(url_for('home'))
        finally:
            cursor.close()
            conexion.close()

    return render_template('login.html')


# destruye la sesion actual del usuario
@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente.', 'success')
    return redirect(url_for('login'))


# limpia el historial y las operaciones pendientes del agente ia
@app.route('/agente/reset', methods=['POST'])
def agente_reset():
    session['agent_history'] = []
    session.pop('agent_secure_value_pending', None)
    session.pop('agent_pending_create', None)
    session.pop('agent_pending_table_delete', None)
    session.pop('agent_pending_record_delete', None)
    return redirect(url_for('agente'))


# habilita el acceso a la base de datos desde el chat tras validar la clave maestra
@app.route('/agente/desbloquear', methods=['POST'])
def agente_desbloquear():
    role = normalize_role(session.get('role'))
    confirmation = require_admin_confirmation(
        'agent_database_unlock',
        {'role': role, 'user_id': session.get('user_id')},
        request.form.get('master_password', ''),
        os.environ.get('MASTER_PASSWORD', ''),
    )
    if confirmation['allowed']:
        session['agent_database_authorized'] = True
        flash('Administración por chat desbloqueada hasta cerrar sesión.', 'success')
    else:
        flash(confirmation['reason'], 'error')
    return redirect(url_for('agente'))


# revoca el acceso a la base de datos en el chat del agente
@app.route('/agente/bloquear', methods=['POST'])
def agente_bloquear():
    session.pop('agent_database_authorized', None)
    session.pop('agent_secure_value_pending', None)
    session.pop('agent_pending_table_delete', None)
    session.pop('agent_pending_record_delete', None)
    session.pop('agent_pending_create', None)
    flash('Las operaciones de base de datos por chat quedaron bloqueadas.', 'success')
    return redirect(url_for('agente'))


# cancela el proceso de vaciado de tabla en el agente
@app.route('/agente/cancelar-borrado-tabla', methods=['POST'])
def agente_cancelar_borrado_tabla():
    session.pop('agent_pending_table_delete', None)
    session.pop('agent_pending_record_delete', None)
    flash('Confirmación de borrado cancelada.', 'success')
    return redirect(url_for('agente'))


# cancela la creacion de un registro guiada por el agente
@app.route('/agente/cancelar-creacion', methods=['POST'])
def agente_cancelar_creacion():
    session.pop('agent_pending_create', None)
    flash('Creación de registro cancelada.', 'success')
    return redirect(url_for('agente'))


# revalida en el servidor los campos del formulario antes de crear el registro
@app.route('/agente/crear-registro', methods=['POST'])
def agente_crear_registro():
    # la sesion guarda que tabla se iba a crear y cuales eran sus campos permitidos
    pending = session.get('agent_pending_create') or {}
    operation = pending.get('operation') or {}
    arguments = operation.get('arguments') or {}
    table = arguments.get('table')
    role = normalize_role(session.get('role'))
    # verifica que la solicitud siga perteneciendo a un administrador con el chat desbloqueado
    if (
        role != 'administrador'
        or not session.get('agent_database_authorized')
        or operation.get('tool_name') != 'create_record'
        or table not in {'user', 'client', 'membership', 'contract', 'payment'}
    ):
        session.pop('agent_pending_create', None)
        flash('La solicitud de creación expiró o ya no está autorizada.', 'error')
        return redirect(url_for('agente'))

    # solo se leen los campos que la base de datos autorizo; no se confia en nombres del navegador
    fields = pending.get('fields') or []
    field_names = {
        field.get('name')
        for field in fields
        if isinstance(field, dict) and isinstance(field.get('name'), str)
    }
    values = {
        name: request.form.get(f'create_field_{name}', '').strip()
        for name in field_names
        if request.form.get(f'create_field_{name}', '').strip()
    }
    # recupera datos que el asistente ya habia entendido y el usuario no tuvo que volver a escribir
    previous_values = arguments.get('values') or {}
    if isinstance(previous_values, dict):
        for name, value in previous_values.items():
            if name in field_names and name not in values:
                values[name] = value

    # si falta algo obligatorio, conserva lo escrito y vuelve a mostrar el formulario sin crear nada
    required_fields = pending.get('required_fields') or []
    missing_fields = [
        name for name in required_fields
        if name not in values or values[name] is None or values[name] == ''
    ]
    if missing_fields:
        pending['missing_fields'] = missing_fields
        pending['values'] = values
        session['agent_pending_create'] = pending
        flash('Completa los campos obligatorios para crear el registro.', 'error')
        return redirect(url_for('agente'))

    user_context = {
        'role': session.get('role', ''),
        'user_id': session.get('user_id'),
        'agent_database_authorized': True,
    }
    # la contrasena solo viaja en el campo privado y nunca se guarda en el historial del chat
    secure_value = request.form.get('secure_value') or None
    # el mismo validador de la herramienta comprueba tipos, columnas y permisos antes del insert
    result = execute_admin_database_tool(
        'create_record',
        {'table': table, 'values': values},
        user_context,
        secure_value=secure_value,
    )
    try:
        creation_result = result if isinstance(result, dict) else json.loads(result)
    except (TypeError, ValueError):
        creation_result = None

    if isinstance(creation_result, dict) and creation_result.get('requires_input'):
        # si el servidor encuentra un campo invalido, mantiene los valores para que se corrijan
        pending['missing_fields'] = creation_result.get('missing_fields', [])
        pending['invalid_fields'] = creation_result.get('invalid_fields', [])
        pending['values'] = values
        session['agent_pending_create'] = pending
        flash('Revisa los campos marcados y vuelve a intentarlo.', 'error')
        return redirect(url_for('agente'))

    if isinstance(creation_result, dict) and creation_result.get('created'):
        # al terminar, elimina la solicitud temporal y muestra el id creado si mysql lo devolvio
        session.pop('agent_pending_create', None)
        session.pop('agent_secure_value_pending', None)
        record_id = creation_result.get('id')
        message = f'Se creó el registro en {table}' + (
            f' con ID {record_id}.' if record_id is not None else '.'
        )
        session.setdefault('agent_history', []).append({
            'role': 'assistant',
            'content': message,
        })
        flash(message, 'success')
        return redirect(url_for('agente'))

    # si el problema no fue un campo corregible, conserva el formulario y muestra el error
    session['agent_pending_create'] = pending
    flash(f'No se pudo crear el registro: {result}', 'error')
    return redirect(url_for('agente'))


# valida la clave destructiva y la frase obligatoria para vaciar una tabla completa
@app.route('/agente/confirmar-borrado-tabla', methods=['POST'])
def agente_confirmar_borrado_tabla():
    # antes de vaciar una tabla, revisa bloqueo, permiso, vencimiento y clave destructiva
    now = time.time()
    locked_until, lockout_available = get_bulk_delete_lockout(session.get('user_id'))
    if not lockout_available:
        flash('No se pudo verificar el bloqueo de seguridad; el vaciado queda deshabilitado.', 'error')
        return redirect(url_for('agente'))
    if now < locked_until:
        remaining = int(locked_until - now) + 1
        flash(f'Borrados masivos bloqueados. Inténtalo de nuevo en {remaining} segundos.', 'error')
        return redirect(url_for('agente'))

    # la tabla se toma de la solicitud guardada en la sesion, no del formulario del navegador
    pending = session.get('agent_pending_table_delete') or {}
    table = pending.get('table')
    if (
        not session.get('agent_database_authorized')
        or table not in BULK_DELETE_TABLES
        or time.time() > float(pending.get('expires_at', 0))
    ):
        session.pop('agent_pending_table_delete', None)
        flash('La solicitud de borrado expiró o ya no está autorizada.', 'error')
        return redirect(url_for('agente'))

    destructive_password = os.environ.get('DESTRUCTIVE_PASSWORD', '')
    master_password = os.environ.get('MASTER_PASSWORD', '')
    if (
        not destructive_password
        or not master_password
        or secrets.compare_digest(destructive_password, master_password)
    ):
        flash('Configura una DESTRUCTIVE_PASSWORD distinta de MASTER_PASSWORD antes de borrar tablas.', 'error')
        return redirect(url_for('agente'))

    supplied_password = request.form.get('destructive_password', '')
    required_phrase = f'ELIMINAR TABLA {table.upper()}'
    supplied_phrase = request.form.get('confirmation_phrase', '').strip().upper()
    if not secrets.compare_digest(supplied_password, destructive_password):
        locked_until = int(time.time()) + BULK_DELETE_LOCKOUT_SECONDS
        set_bulk_delete_lockout(session.get('user_id'), locked_until)
        session.pop('agent_pending_table_delete', None)
        app.logger.warning(
            'Bulk delete lockout: user_id=%s duration_seconds=%s',
            session.get('user_id'),
            BULK_DELETE_LOCKOUT_SECONDS,
        )
        flash('Segunda contraseña incorrecta. Los borrados masivos quedan bloqueados por tres minutos.', 'error')
        return redirect(url_for('agente'))

    if not secrets.compare_digest(supplied_phrase, required_phrase):
        pending['attempts'] = int(pending.get('attempts', 0)) + 1
        if pending['attempts'] >= 3:
            session.pop('agent_pending_table_delete', None)
            flash('Se canceló la solicitud tras tres confirmaciones incorrectas.', 'error')
        else:
            session['agent_pending_table_delete'] = pending
            flash('La segunda contraseña o la frase de confirmación no coincide.', 'error')
        return redirect(url_for('agente'))

    # cuenta primero para registrar cuantas filas se quitaron en la bitacora
    connection = get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(f'SELECT COUNT(*) FROM `{table}`')
        row_count = int(cursor.fetchone()[0])
        cursor.execute(f'DELETE FROM `{table}`')
        connection.commit()
        app.logger.warning(
            'Admin table wipe: user_id=%s table=%s rows=%s',
            session.get('user_id'),
            table,
            row_count,
        )
        session.pop('agent_pending_table_delete', None)
        session.setdefault('agent_history', []).append({
            'role': 'assistant',
            'content': f'Tabla {table} vaciada. Se eliminaron {row_count} registros.',
        })
        flash(f'Tabla {table} vaciada. Se eliminaron {row_count} registros.', 'success')
    except Exception:
        connection.rollback()
        flash('No se pudo vaciar la tabla; la base rechazó la operación.', 'error')
    finally:
        cursor.close()
        connection.close()
    return redirect(url_for('agente'))


# ejecuta la eliminacion de cinco o mas registros especificos tras confirmar con Destructive Password
@app.route('/agente/confirmar-borrado-registros', methods=['POST'])
def agente_confirmar_borrado_registros():
    # primero comprueba el bloqueo comun, que impide reintentar un borrado masivo durante unos minutos
    now = time.time()
    locked_until, lockout_available = get_bulk_delete_lockout(session.get('user_id'))
    if not lockout_available:
        flash('No se pudo verificar el bloqueo de seguridad; el borrado queda deshabilitado.', 'error')
        return redirect(url_for('agente'))
    if now < locked_until:
        remaining = int(locked_until - now) + 1
        flash(f'Borrados masivos bloqueados. Inténtalo de nuevo en {remaining} segundos.', 'error')
        return redirect(url_for('agente'))

    # recupera los ids que el administrador pidio borrar y comprueba permiso y vencimiento
    pending = session.get('agent_pending_record_delete') or {}
    operation = pending.get('operation') or {}
    arguments = operation.get('arguments') or {}
    table = pending.get('table')
    ids = arguments.get('ids') or []
    target_count = len(ids) if isinstance(ids, list) else 0
    if (
        not session.get('agent_database_authorized')
        or operation.get('tool_name') != 'delete_record'
        or table not in {'user', 'client', 'membership', 'contract', 'payment'}
        or arguments.get('table') != table
        or target_count < 5
        or time.time() > float(pending.get('expires_at', 0))
    ):
        session.pop('agent_pending_record_delete', None)
        flash('La solicitud de borrado expiró o ya no está autorizada.', 'error')
        return redirect(url_for('agente'))

    destructive_password = os.environ.get('DESTRUCTIVE_PASSWORD', '')
    master_password = os.environ.get('MASTER_PASSWORD', '')
    if (
        not destructive_password
        or not master_password
        or secrets.compare_digest(destructive_password, master_password)
    ):
        flash('Configura una DESTRUCTIVE_PASSWORD distinta de MASTER_PASSWORD antes de borrar cinco o más registros.', 'error')
        return redirect(url_for('agente'))

    # pide la Destructive Password y la frase con tabla y cantidad
    supplied_password = request.form.get('destructive_password', '')
    required_phrase = f'ELIMINAR {target_count} REGISTROS DE {table.upper()}'
    supplied_phrase = request.form.get('confirmation_phrase', '').strip().upper()
    if not secrets.compare_digest(supplied_password, destructive_password):
        locked_until = int(time.time()) + BULK_DELETE_LOCKOUT_SECONDS
        set_bulk_delete_lockout(session.get('user_id'), locked_until)
        session.pop('agent_pending_record_delete', None)
        app.logger.warning(
            'Bulk record delete lockout: user_id=%s duration_seconds=%s',
            session.get('user_id'),
            BULK_DELETE_LOCKOUT_SECONDS,
        )
        flash('Destructive Password incorrecta. Los borrados masivos quedan bloqueados por tres minutos.', 'error')
        return redirect(url_for('agente'))

    if not secrets.compare_digest(supplied_phrase, required_phrase):
        pending['attempts'] = int(pending.get('attempts', 0)) + 1
        if pending['attempts'] >= 3:
            session.pop('agent_pending_record_delete', None)
            flash('Se canceló la solicitud tras tres confirmaciones incorrectas.', 'error')
        else:
            session['agent_pending_record_delete'] = pending
            flash('La frase de confirmación no coincide.', 'error')
        return redirect(url_for('agente'))

    user_context = {
        'role': session.get('role', ''),
        'user_id': session.get('user_id'),
        'agent_database_authorized': True,
        'destructive_password_confirmed': True,
    }
    # ejecuta los ids guardados al pedir la confirmacion; ignora cualquier id enviado por el navegador
    result = execute_admin_database_tool('delete_record', arguments, user_context)
    try:
        deletion_result = result if isinstance(result, dict) else json.loads(result)
    except (TypeError, ValueError):
        deletion_result = None

    if isinstance(deletion_result, dict) and 'deleted' in deletion_result:
        deleted_count = int(deletion_result['deleted'])
        message = f'Se eliminaron {deleted_count} registros de {table}.'
        app.logger.warning(
            'Admin multi-record delete: user_id=%s table=%s requested=%s deleted=%s',
            session.get('user_id'),
            table,
            target_count,
            deleted_count,
        )
        flash(message, 'success')
    else:
        message = str(result)
        flash(f'No se pudo completar el borrado: {message}', 'error')
    session.pop('agent_pending_record_delete', None)
    session.setdefault('agent_history', []).append({'role': 'assistant', 'content': message})
    return redirect(url_for('agente'))


# interfaz principal del chat inteligente y manejo de peticiones operativas
@app.route('/agente', methods=['GET', 'POST'])
def agente():
    session.setdefault('agent_csrf_token', secrets.token_urlsafe(32))
    user_context = {
        'role': session.get('role', 'Usuario'),
        'name': session.get('nombre_completo', 'Usuario'),
        'user_id': session.get('user_id'),
        **session.get('permissions', {}),
        'agent_database_authorized': bool(session.get('agent_database_authorized')),
    }
    is_admin = can_access_agent(session.get('permissions', {}), session.get('role', ''))

    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) AS total_usuarios FROM `user`")
        total_usuarios = cursor.fetchone()['total_usuarios'] or 0

        cursor.execute("SELECT COUNT(*) AS total_clientes FROM client")
        total_clientes = cursor.fetchone()['total_clientes'] or 0

        cursor.execute("SELECT COUNT(*) AS total_contratos FROM contract")
        total_contratos = cursor.fetchone()['total_contratos'] or 0

        cursor.execute("SELECT COALESCE(SUM(amount), 0) AS total_pagado FROM payment")
        total_pagado = float(cursor.fetchone()['total_pagado'] or 0)

        stats = {
            'usuarios': total_usuarios,
            'clientes': total_clientes,
            'contratos': total_contratos,
            'pagos': total_pagado,
        }
    finally:
        cursor.close()
        conexion.close()

    quick_prompts = get_agent_quick_prompts(user_context)

    history = session.get('agent_history')
    if isinstance(history, list):
        history = _remove_internal_security_messages(history)
        session['agent_history'] = history
    if history is None:
        is_client = session.get('role', '').lower() in {'usuario final', 'cliente'}
        welcome = (
            f'Hola, {session.get("nombre_completo", "usuario")}. Soy el agente IA de LUNA y estoy adaptado a tu perfil de '
            f'{session.get("role", "usuario")}. Puedo ayudarte con consultas operativas y datos autorizados.'
        )
        if is_client:
            welcome += ' También puedo recomendarte música según tus gustos.'
        history = [{'role': 'assistant', 'content': welcome}]
        session['agent_history'] = history

    if request.method == 'POST':
        prompt = (request.form.get('prompt') or '').strip()
        secure_value = request.form.get('secure_value') or None
        history = session.get('agent_history', [])
        # comprueba que formulario esta pendiente para no mezclar contrasena, alta o borrado con otro mensaje
        secure_value_pending = bool(
            session.get('agent_secure_value_pending')
            or agent_is_waiting_for_secure_value(history)
        )
        destructive_confirmation_pending = bool(
            session.get('agent_pending_table_delete')
            or session.get('agent_pending_record_delete')
        )
        if prompt and (
            destructive_confirmation_pending
            or session.get('agent_pending_create')
        ):
            flash('Completa o cancela el recuadro pendiente antes de enviar otra solicitud.', 'error')
            return redirect(url_for('agente'))
        if not secure_value_pending or destructive_confirmation_pending:
            secure_value = None
        if not prompt and not (secure_value and secure_value_pending):
            flash('Escribe una pregunta para el agente.', 'error')
            return redirect(url_for('agente'))

        history.append({
            'role': 'user',
            'content': prompt or 'Envié la contraseña solicitada mediante el campo seguro.',
        })

        bulk_delete_target = classify_bulk_delete_request(prompt)
        if bulk_delete_target:
            # el borrado de una tabla completa requiere un panel de confirmacion aparte
            session.pop('agent_pending_create', None)
            session.pop('agent_pending_record_delete', None)
            session.pop('agent_pending_table_delete', None)
            if bulk_delete_target == 'database':
                answer = 'El borrado completo de la base de datos está bloqueado desde el chat.'
            elif bulk_delete_target == 'user':
                answer = 'No se permite vaciar la tabla de usuarios desde el chat; eliminarla impediría iniciar sesión.'
            elif bulk_delete_target == 'unknown':
                answer = 'Indica una tabla permitida para solicitar el borrado completo.'
            elif not user_context['agent_database_authorized']:
                answer = 'Desbloquea el agente con Master Password antes de solicitar cambios en la base.'
            else:
                locked_until, lockout_available = get_bulk_delete_lockout(session.get('user_id'))
                if not lockout_available:
                    answer = 'No se pudo verificar el bloqueo de seguridad; el vaciado queda deshabilitado.'
                elif time.time() < locked_until:
                    remaining = int(locked_until - time.time()) + 1
                    answer = f'Los borrados masivos están bloqueados. Inténtalo de nuevo en {remaining} segundos.'
                else:
                    session['agent_pending_table_delete'] = {
                        'table': bulk_delete_target,
                        'expires_at': time.time() + BULK_DELETE_CONFIRMATION_WINDOW,
                        'attempts': 0,
                    }
                    session.pop('agent_pending_create', None)
                    answer = (
                        f'Borrado masivo solicitado para {bulk_delete_target}. '
                        f'Para continuar, confirma en el panel con la contraseña destructiva y escribe '
                        f'ELIMINAR TABLA {bulk_delete_target.upper()}. '
                        'La solicitud expira en cinco minutos. La base completa y la tabla user están protegidas.'
                    )
            history.append({'role': 'assistant', 'content': answer})
            session['agent_history'] = history
            return redirect(url_for('agente'))

        records_table = detect_admin_records_table_request(prompt)
        if is_admin and user_context['agent_database_authorized'] and records_table:
            table_labels = {
                'user': 'personal',
                'client': 'clientes',
                'membership': 'planes y membresías',
                'contract': 'contratos',
                'payment': 'pagos',
            }
            history.append({
                'role': 'assistant',
                'content': f'Te muestro los registros de {table_labels[records_table]} en páginas de 100.',
            })
            session['agent_history'] = history
            return redirect(url_for('agente', records_table=records_table, records_page=1))

        try:
            answer = generate_agent_response(
                prompt,
                user_context,
                secure_value=secure_value,
                conversation_history=history,
            )
        except Exception as exc:
            answer = f'Ocurrió un error al procesar la solicitud: {exc}'

        secure_value_requested = (
            isinstance(answer, dict)
            and answer.get('requires_secure_value')
        )
        # cuando faltan datos, prepara el formulario usando solo los campos reales de la tabla
        create_form_requested = (
            isinstance(answer, dict)
            and answer.get('requires_input')
            and isinstance(answer.get('pending_create'), dict)
        )
        if create_form_requested:
            # conserva en la sesion solo la tabla y los datos aceptados para poder mostrarlos en el formulario
            pending_operation = answer['pending_create']
            pending_arguments = pending_operation.get('arguments') or {}
            pending_values = pending_arguments.get('values') or {}
            table = pending_arguments.get('table')
            fields = answer.get('fields') or []
            allowed_field_names = {
                field.get('name')
                for field in fields
                if isinstance(field, dict) and isinstance(field.get('name'), str)
            }
            safe_values = {
                name: value
                for name, value in pending_values.items()
                if name in allowed_field_names
                and (value is None or isinstance(value, (str, int, float, bool)))
            } if isinstance(pending_values, dict) else {}
            session['agent_pending_create'] = {
                'operation': {
                    'tool_name': 'create_record',
                    'arguments': {'table': table, 'values': safe_values},
                },
                'fields': fields,
                'required_fields': answer.get('required_fields') or [],
                'missing_fields': answer.get('missing_fields') or [],
                'invalid_fields': answer.get('invalid_fields') or [],
                'secure_password_required': bool(answer.get('secure_password_required')),
            }
            session.pop('agent_secure_value_pending', None)
            session.pop('agent_pending_table_delete', None)
            session.pop('agent_pending_record_delete', None)
            # la siguiente pantalla mostrara el formulario y esperara que el administrador lo envie
            answer = f'Para crear el registro en {table}, completa los campos del formulario que aparece en este chat.'
        elif secure_value_requested:
            answer = str(answer.get('message') or 'Ingresa la contraseña solicitada en el recuadro seguro separado.')

        if isinstance(answer, dict) and answer.get('requires_confirmation'):
            # guarda el borrado solicitado para ejecutarlo solo despues de confirmar en el panel rojo
            pending_operation = answer.get('pending_delete')
            pending_arguments = (pending_operation or {}).get('arguments') or {}
            pending_ids = pending_arguments.get('ids') or []
            pending_table = pending_arguments.get('table')
            # Solo una lista concreta de cinco o más IDs activa la confirmación destructiva.
            if (
                (pending_operation or {}).get('tool_name') == 'delete_record'
                and isinstance(pending_ids, list)
                and len(pending_ids) >= 5
                and pending_table in {'user', 'client', 'membership', 'contract', 'payment'}
            ):
                # la operacion queda pendiente; aun no se borra nada en este paso
                count = len(pending_ids)
                session['agent_pending_record_delete'] = {
                    'table': pending_table,
                    'count': count,
                    'operation': pending_operation,
                    'expires_at': time.time() + BULK_DELETE_CONFIRMATION_WINDOW,
                    'attempts': 0,
                }
                session.pop('agent_pending_table_delete', None)
                session.pop('agent_pending_create', None)
                answer = (
                    f'Solicitud de borrado de {count} registros de {pending_table}. '
                    'Confirma con Destructive Password en el recuadro de seguridad para continuar.'
                )
            else:
                reason = answer.get('reason')
                if isinstance(reason, str) and reason:
                    answer = (
                        f'No se pudo abrir el panel de seguridad. '
                        f'La operación no se ejecutó. {reason}'
                    )
                else:
                    answer = 'No se pudo abrir el panel de seguridad. La operación no se ejecutó.'

        history.append({'role': 'assistant', 'content': answer})
        session['agent_history'] = history
        answer_lower = answer.lower()
        session['agent_secure_value_pending'] = bool(
            is_admin
            and not secure_value
            and not create_form_requested
            and (
                secure_value_requested
                or ('campo seguro' in answer_lower and 'contraseña' in answer_lower)
            )
        )
        return redirect(url_for('agente'))

    records_page = None
    requested_table = request.args.get('records_table', '')
    destructive_password = os.environ.get('DESTRUCTIVE_PASSWORD', '')
    configured_master_password = os.environ.get('MASTER_PASSWORD', '')
    destructive_delete_configured = bool(
        destructive_password
        and configured_master_password
        and not secrets.compare_digest(destructive_password, configured_master_password)
    )
    requested_page = request.args.get('records_page', type=int)
    if requested_table and requested_page and is_admin and user_context['agent_database_authorized']:
        try:
            records_page = get_admin_records_page(requested_table, user_context, requested_page)
        except (PermissionError, ValueError):
            flash('No se pudo autorizar la lista de registros.', 'error')

    return render_template(
        'agente.html',
        stats=stats,
        messages=session.get('agent_history', history),
        quick_prompts=quick_prompts,
        role_label=session.get('role', 'Usuario'),
        is_admin=is_admin,
        agent_database_authorized=bool(session.get('agent_database_authorized')),
        secure_value_pending=bool(
            session.get('agent_secure_value_pending')
            or agent_is_waiting_for_secure_value(session.get('agent_history', history))
        ),
        pending_table_delete=session.get('agent_pending_table_delete'),
        pending_record_delete=session.get('agent_pending_record_delete'),
        pending_create=session.get('agent_pending_create'),
        destructive_delete_configured=destructive_delete_configured,
        agent_csrf_token=session['agent_csrf_token'],
        records_page=records_page,
        records_table_label={
            'user': 'Personal',
            'client': 'Clientes',
            'membership': 'Planes y membresías',
            'contract': 'Contratos',
            'payment': 'Pagos',
        }.get(requested_table),
        role_view_role=get_role_view(user_context)['role'],
    )


# plantilla base de la interfaz general
@app.route('/base')
def base():
    return render_template('base.html')


# vista principal del sistema adaptada al perfil del usuario
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    permissions = {
        'role': session.get('role', 'Usuario'),
        **session.get('permissions', {}),
    }
    role_view = get_role_view(permissions)
    return render_template(
        role_view['template'],
        role_view=role_view,
        role_label=role_view['role'],
        username=session.get('username', 'usuario'),
        nombre_completo=session.get('nombre_completo', 'Usuario'),
    )


# --- crud staff / personal ---------------------------------------------------------
# muestra la lista de empleados
@app.route('/staff', methods=['GET'])
def staff_form():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)  # regresa diccionarios para la plantilla
    cursor.execute("""
        SELECT id, name AS nombre, lastname AS apellido,
               username AS usuario, email AS correo
        FROM user
    """)
    lista_staff = cursor.fetchall()
    cursor.close()
    conexion.close()
    return render_template('staff_form.html', lista_staff=lista_staff, staff_editar=None)


# registra un nuevo empleado en el sistema
@app.route('/staff/guardar', methods=['POST'])
def staff_guardar():
    nombre = request.form.get('nombre', '')
    apellido = request.form.get('apellido', '')
    usuario = request.form.get('usuario', '')
    correo = request.form.get('correo', '')
    password = request.form.get('password', '')

    # validar que no haya campos vacios
    if not all([nombre.strip(), apellido.strip(), usuario.strip(), correo.strip(), password.strip()]):
        flash("Todos los campos son obligatorios", "error")
        return redirect(url_for('staff_form'))

    conexion = get_connection()
    cursor = conexion.cursor()

    # consultar si el username o correo ya existen en la base de datos
    cursor.execute(
        "SELECT id FROM user WHERE username = %s OR email = %s",
        (usuario, correo)
    )
    usuario_existente = cursor.fetchone()

    # si encontramos una coincidencia, detenemos el registro
    if usuario_existente:
        cursor.close()
        conexion.close()
        flash("El nombre de usuario o correo ya esta en uso", "error")
        return redirect(url_for('staff_form'))

    # si no existe duplicado, insertamos al nuevo empleado
    cursor.execute(
        "INSERT INTO user (name, lastname, username, email, password) VALUES (%s, %s, %s, %s, %s)",
        (nombre, apellido, usuario, correo, password)
    )
    conexion.commit()
    cursor.close()
    conexion.close()

    flash("Empleado registrado correctamente", "success")
    return redirect(url_for('staff_form'))


# recupera los datos de un empleado para edicion
@app.route('/staff/editar/<int:id>', methods=['GET'])
def staff_editar(id):
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        # hace select del user a editar y lo guarda en persona
        cursor.execute("""
            SELECT id, name AS nombre, lastname AS apellido,
                   username AS usuario, email AS correo
            FROM user WHERE id = %s
        """, (id,))
        persona = cursor.fetchone()

        # si el usuario no existe en la bd
        if not persona:
            flash("El empleado que intentas editar no existe.", "error")
            return redirect(url_for('staff_form'))

        # cargar la lista completa de empleados para la tabla
        cursor.execute("""
            SELECT id, name AS nombre, lastname AS apellido,
                   username AS usuario, email AS correo
            FROM user
        """)
        lista_staff = cursor.fetchall()

        return render_template('staff_form.html', lista_staff=lista_staff, staff_editar=persona)

    except Exception as e:
        flash("Ocurrio un error al recuperar la informacion del empleado.", "error")
        return redirect(url_for('staff_form'))

    finally:
        cursor.close()
        conexion.close()


# actualiza la informacion de un empleado en la base de datos
@app.route('/staff/actualizar/<int:id>', methods=['POST'])
def staff_actualizar(id):
    nombre = request.form.get('nombre', '').strip()
    apellido = request.form.get('apellido', '').strip()
    usuario = request.form.get('usuario', '').strip()
    correo = request.form.get('correo', '').strip()

    # rechazar campos vacios
    if not all([nombre, apellido, usuario, correo]):
        flash("Todos los campos (Nombre, Apellido, Usuario, Correo) son obligatorios.", "error")
        return redirect(url_for('staff_editar', id=id))

    # validacion de correo regex
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, correo):
        flash("El formato del correo electronico no es valido.", "error")
        return redirect(url_for('staff_editar', id=id))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # buscamos si hay ya un nombre de usuario igual
        cursor.execute("SELECT id FROM user WHERE username = %s AND id != %s", (usuario, id))
        if cursor.fetchone():
            flash(f"El nombre de usuario '{usuario}' ya esta en uso por otro empleado.", "error")
            return redirect(url_for('staff_editar', id=id))

        # ahora seguimos con el correo
        cursor.execute("SELECT id FROM user WHERE email = %s AND id != %s", (correo, id))
        if cursor.fetchone():
            flash(f"El correo electronico '{correo}' ya esta en uso por otro empleado.", "error")
            return redirect(url_for('staff_editar', id=id))

        # actualiza los datos
        cursor.execute("""
            UPDATE user 
            SET name = %s, lastname = %s, username = %s, email = %s
            WHERE id = %s
        """, (nombre, apellido, usuario, correo, id))
        
        conexion.commit()
        flash("Datos del empleado actualizados correctamente.", "success")
        return redirect(url_for('staff_form'))

    except Exception as e:
        conexion.rollback()
        flash("Ocurrio un problema en la base de datos al intentar actualizar.", "error")
        return redirect(url_for('staff_editar', id=id))

    finally:
        cursor.close()
        conexion.close()


# elimina un empleado y sus pagos asociados
@app.route('/staff/eliminar/<int:id>', methods=['POST'])
def staff_eliminar(id):
    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # la tabla payment tiene user_id not null; se eliminan primero sus pagos
        cursor.execute("DELETE FROM payment WHERE user_id = %s", (id,))
        cursor.execute("DELETE FROM user WHERE id = %s", (id,))

        conexion.commit()
        flash("Empleado eliminado permanentemente de la base de datos.", "success")

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR AL BORRAR STAFF: {e} ---")
        flash(f"Error al eliminar de la base de datos: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('staff_form'))


# --- crud clientes ------------------------------------------------------------------
# muestra el listado de clientes
@app.route('/clientes', methods=['GET'])
def clientes_form():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT id, 
                   name AS nombre, 
                   lastname AS apellido, 
                   email AS correo, 
                   phone AS telefono, 
                   identity_card AS documento 
            FROM client
        """)
        lista_clientes = cursor.fetchall()
        return render_template('clientes_form.html', lista_clientes=lista_clientes, cliente_editar=None)
    
    except Exception as e:
        print(f"--- ERROR MYSQL AL CARGAR CLIENTES: {e} ---")
        flash(f"Error al cargar clientes: {e}", "error")
        return render_template('clientes_form.html', lista_clientes=[], cliente_editar=None)
        
    finally:
        cursor.close()
        conexion.close()


# guarda un nuevo cliente en la base de datos
@app.route('/clientes/guardar', methods=['POST'])
def clientes_guardar():
    nombre = request.form.get('nombre', '').strip()
    apellido = request.form.get('apellido', '').strip()
    documento = request.form.get('documento', '').strip()
    correo = request.form.get('correo', '').strip()
    telefono = request.form.get('telefono', '').strip()

    # campos vacios
    if not all([nombre, apellido, documento, correo, telefono]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('clientes_form'))

    # correo
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, correo):
        flash("El formato del correo electronico no es valido.", "error")
        return redirect(url_for('clientes_form'))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # validar duplicado de correo
        cursor.execute("SELECT id FROM client WHERE email = %s", (correo,))
        if cursor.fetchone():
            flash(f"El correo '{correo}' ya esta registrado con otro cliente.", "error")
            return redirect(url_for('clientes_form'))

        # revisar duplicado de documento
        cursor.execute("SELECT id FROM client WHERE identity_card = %s", (documento,))
        if cursor.fetchone():
            flash(f"El documento '{documento}' ya esta registrado con otro cliente.", "error")
            return redirect(url_for('clientes_form'))

        # insertar nuevo cliente 
        cursor.execute(
            """
            INSERT INTO client (name, lastname, identity_card, email, phone) 
            VALUES (%s, %s, %s, %s, %s)
            """,
            (nombre, apellido, documento, correo, telefono)
        )
        conexion.commit()
        flash("Cliente registrado correctamente.", "success")

    except Exception as e:
        conexion.rollback()
        print(f"Error detallado de MySQL: {e}")
        flash(f"Error al registrar el cliente: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('clientes_form'))


# obtiene datos de un cliente para su modificacion
@app.route('/clientes/editar/<int:id>', methods=['GET'])
def clientes_editar(id):
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        # hace select del cliente a editar y lo guarda en cliente
        cursor.execute("""
            SELECT id, name AS nombre, lastname AS apellido, email AS correo, phone AS telefono, identity_card AS documento   
            FROM client WHERE id = %s
        """, (id,))
        cliente = cursor.fetchone()

        # si el cliente no existe en la bd
        if not cliente:
            flash("El cliente que intentas editar no existe.", "error")
            return redirect(url_for('clientes_form'))

        # cargar la lista completa de clientes para la tabla
        cursor.execute("""
            SELECT id, name AS nombre, lastname AS apellido, email AS correo, phone AS telefono, identity_card AS documento
            FROM client
        """)
        lista_clientes = cursor.fetchall()

        return render_template('clientes_form.html', lista_clientes=lista_clientes, cliente_editar=cliente)

    except Exception as e:
        flash("Ocurrio un error al recuperar la informacion del cliente.", "error")
        return redirect(url_for('clientes_form'))

    finally:
        cursor.close()
        conexion.close()


# actualiza los datos de un cliente existente
@app.route('/clientes/actualizar/<int:id>', methods=['POST'])
def clientes_actualizar(id):
    nombre = request.form.get('nombre', '').strip()
    apellido = request.form.get('apellido', '').strip()
    documento = request.form.get('documento', '').strip()
    correo = request.form.get('correo', '').strip()
    telefono = request.form.get('telefono', '').strip()

    # validar campos vacios
    if not all([nombre, apellido, documento, correo, telefono]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('clientes_editar', id=id))

    # validar formato de correo
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, correo):
        flash("El formato del correo electronico no es valido.", "error")
        return redirect(url_for('clientes_editar', id=id))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        cursor.execute("SELECT id FROM client WHERE email = %s AND id != %s", (correo, id))
        if cursor.fetchone():
            flash(f"El correo '{correo}' ya esta en uso por otro cliente.", "error")
            return redirect(url_for('clientes_editar', id=id))

        cursor.execute("SELECT id FROM client WHERE identity_card = %s AND id != %s", (documento, id))
        if cursor.fetchone():
            flash(f"El documento '{documento}' ya esta en uso por otro cliente.", "error")
            return redirect(url_for('clientes_editar', id=id))
        
        # actualizar cliente
        cursor.execute("""
            UPDATE client 
            SET name = %s, lastname = %s, email = %s, phone = %s, identity_card = %s
            WHERE id = %s
        """, (nombre, apellido, correo, telefono, documento, id))
        
        conexion.commit()
        flash("Datos del cliente actualizados correctamente.", "success")
        return redirect(url_for('clientes_form'))

    except Exception as e:
        conexion.rollback()
        flash("Ocurrio un problema en la base de datos al intentar actualizar.", "error")
        return redirect(url_for('clientes_editar', id=id))

    finally:
        cursor.close()
        conexion.close()


# borra cliente, suscripciones y pagos vinculados
@app.route('/clientes/eliminar/<int:id>', methods=['POST'])
def clientes_eliminar(id):
    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # 1. borrar primero los pagos vinculados a las suscripciones de este cliente
        cursor.execute("""
            DELETE p FROM payment p 
            INNER JOIN contract c ON p.contract_id = c.id 
            WHERE c.client_id = %s
        """, (id,))
        
        # 2. borrar las suscripciones del cliente
        cursor.execute("DELETE FROM contract WHERE client_id = %s", (id,))
        
        # 3. borrar definitivamente al cliente de la bd
        cursor.execute("DELETE FROM client WHERE id = %s", (id,))
        
        conexion.commit()
        flash("Cliente y su historial eliminados permanentemente.", "success")

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR AL BORRAR CLIENTE: {e} ---")
        flash(f"Error al eliminar de la base de datos: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('clientes_form'))


# --- crud planes --------------------------------------------------------------------
# consulta y muestra los planes de membresia
@app.route('/planes', methods=['GET'])  
def planes_form():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT id, name AS nombre, description AS descripcion, price AS precio, duration_days AS duracion
            FROM membership
        """)
        lista_planes = cursor.fetchall()
        return render_template('planes_form.html', lista_planes=lista_planes, plan_editar=None)
    
    except Exception as e:
        print(f"--- ERROR MYSQL AL CARGAR PLANES: {e} ---")
        flash(f"Error al cargar planes: {e}", "error")
        return render_template('planes_form.html', lista_planes=[], plan_editar=None)
        
    finally:
        cursor.close()
        conexion.close()


# inserta un nuevo plan de membresia
@app.route('/planes/guardar', methods=['POST'])
def planes_guardar():
    nombre = request.form.get('nombre', '').strip()
    descripcion = request.form.get('descripcion', '').strip()
    precio = request.form.get('precio', '').strip()
    duracion = request.form.get('duracion', '').strip()

    # validar campos vacios
    if not all([nombre, descripcion, precio, duracion]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('planes_form'))

    # validar precio y duracion
    try:
        precio_val = float(precio)
        duracion_val = int(duracion)
        if precio_val <= 0 or duracion_val <= 0:
            raise ValueError
    except ValueError:
        flash("El precio y la duracion deben ser valores numericos mayores a cero.", "error")
        return redirect(url_for('planes_form'))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # insertar nuevo plan
        cursor.execute(
            """
            INSERT INTO membership (name, description, price, duration_days) 
            VALUES (%s, %s, %s, %s)
            """,
            (nombre, descripcion, precio_val, duracion_val)
        )
        conexion.commit()
        flash("Plan registrado correctamente.", "success")

    except Exception as e:
        conexion.rollback()
        print(f"Error detallado de MySQL: {e}")
        flash(f"Error al registrar el plan: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('planes_form'))


# carga los datos de un plan para su modificacion
@app.route('/planes/editar/<int:id>', methods=['GET'])
def planes_editar(id):
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        # hace select del plan a editar y lo guarda en plan
        cursor.execute("""
            SELECT id, name AS nombre, description AS descripcion, price AS precio, duration_days AS duracion   
            FROM membership WHERE id = %s
        """, (id,))
        plan = cursor.fetchone()

        # si el plan no existe en la bd
        if not plan:
            flash("El plan que intentas editar no existe.", "error")
            return redirect(url_for('planes_form'))

        # cargar la lista completa de planes para la tabla
        cursor.execute("""
            SELECT id, name AS nombre, description AS descripcion, price AS precio, duration_days AS duracion
            FROM membership
        """)
        lista_planes = cursor.fetchall()

        return render_template('planes_form.html', lista_planes=lista_planes, plan_editar=plan)

    except Exception as e:
        flash("Ocurrio un error al recuperar la informacion del plan.", "error")
        return redirect(url_for('planes_form'))

    finally:
        cursor.close()
        conexion.close()


# actualiza los datos de un plan existente
@app.route('/planes/actualizar/<int:id>', methods=['POST'])
def planes_actualizar(id):
    nombre = request.form.get('nombre', '').strip()
    descripcion = request.form.get('descripcion', '').strip()
    precio = request.form.get('precio', '').strip()
    duracion = request.form.get('duracion', '').strip()

    # validar campos vacios
    if not all([nombre, descripcion, precio, duracion]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('planes_editar', id=id))

    # validar precio y duracion
    try:
        precio_val = float(precio)
        duracion_val = int(duracion)
        if precio_val <= 0 or duracion_val <= 0:
            raise ValueError
    except ValueError:
        flash("El precio y la duracion deben ser valores numericos mayores a cero.", "error")
        return redirect(url_for('planes_editar', id=id))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # actualizar plan
        cursor.execute("""
            UPDATE membership 
            SET name = %s, description = %s, price = %s, duration_days = %s
            WHERE id = %s
        """, (nombre, descripcion, precio_val, duracion_val, id))
        
        conexion.commit()
        flash("Datos del plan actualizados correctamente.", "success")

    except Exception as e:
        conexion.rollback()
        flash("Ocurrio un problema en la base de datos al intentar actualizar.", "error")
        return redirect(url_for('planes_editar', id=id))

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('planes_form'))


# elimina un plan y sus suscripciones asociadas
@app.route('/planes/eliminar/<int:id>', methods=['POST'])
def planes_eliminar(id):
    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # 1. borrar los pagos vinculados a contratos con este plan
        cursor.execute("""
            DELETE p FROM payment p 
            INNER JOIN contract c ON p.contract_id = c.id 
            WHERE c.membership_id = %s
        """, (id,))
        
        # 2. borrar las suscripciones asociadas a este plan
        cursor.execute("DELETE FROM contract WHERE membership_id = %s", (id,))
        
        # 3. borrar fisicamente el plan de la bd
        cursor.execute("DELETE FROM membership WHERE id = %s", (id,))
        
        conexion.commit()
        flash("Plan eliminado permanentemente de la base de datos.", "success")

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR AL BORRAR PLAN: {e} ---")
        flash(f"Error al eliminar de la base de datos: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('planes_form'))


# --- crud suscripciones / contratos ------------------------------------------------
# lista suscripciones, clientes activos y planes disponibles
@app.route('/suscripciones', methods=['GET'])
def suscripciones_form():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        # el select concatena nombre y apellido para el combo box
        cursor.execute("""
            SELECT id, CONCAT(name, ' ', lastname) AS nombre_completo, email 
            FROM client 
            WHERE is_active = 1
        """)
        lista_clientes = cursor.fetchall()

        # trae los planes activos para el combo box
        cursor.execute("""
            SELECT id, name AS nombre, price AS precio, duration_days AS duracion 
            FROM membership 
            WHERE is_active = 1
        """)
        lista_planes = cursor.fetchall()

        # inner join para traer los datos completos del contrato
        cursor.execute("""
            SELECT 
                c.id,
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre, 
                m.name AS plan_nombre,
                c.start_date AS fecha_inicio,
                c.end_date AS fecha_fin,
                c.status AS estado
            FROM contract c
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN membership m ON c.membership_id = m.id
            ORDER BY c.id DESC
        """)
        lista_suscripciones = cursor.fetchall()

        return render_template(
            'suscripciones_form.html', 
            lista_clientes=lista_clientes, 
            lista_planes=lista_planes, 
            lista_suscripciones=lista_suscripciones
        )

    except Exception as e:
        print(f"--- ERROR AL CARGAR SUSCRIPCIONES: {e} ---")
        flash(f"Error al cargar el modulo: {e}", "error")
        return render_template('suscripciones_form.html', lista_clientes=[], lista_planes=[], lista_suscripciones=[])
        
    finally:
        cursor.close()
        conexion.close()


# registra una nueva suscripcion calculando la fecha de vencimiento
@app.route('/suscripciones/guardar', methods=['POST'])
def suscripciones_guardar():
    cliente_id = request.form.get('cliente_id', '').strip()
    membresia_id = request.form.get('membresia_id', '').strip()
    fecha_inicio_str = request.form.get('fecha_inicio', '').strip()
    estado = request.form.get('estado', '').strip()

    # validacion de campos vacios
    if not all([cliente_id, membresia_id, fecha_inicio_str, estado]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('suscripciones_form'))

    # el estado debe ser 1 o 0
    if estado not in ('0', '1'):
        flash("El estado seleccionado no es valido.", "error")
        return redirect(url_for('suscripciones_form'))

    # valida que los id sean enteros positivos
    try:
        cliente_id_int = int(cliente_id)
        membresia_id_int = int(membresia_id)
        if cliente_id_int <= 0 or membresia_id_int <= 0:
            raise ValueError
    except ValueError:
        flash("Cliente y plan deben seleccionarse correctamente.", "error")
        return redirect(url_for('suscripciones_form'))

    # convierte la fecha de texto a objeto date
    try:
        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
    except ValueError:
        flash("El formato de fecha ingresado no es valido.", "error")
        return redirect(url_for('suscripciones_form'))

    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        # validar que el cliente exista
        cursor.execute("SELECT id FROM client WHERE id = %s AND is_active = 1", (cliente_id_int,))
        if not cursor.fetchone():
            flash("El cliente seleccionado no existe o no esta activo.", "error")
            return redirect(url_for('suscripciones_form'))

        # evita suscripciones duplicadas activas para el mismo cliente
        cursor.execute("SELECT id FROM contract WHERE client_id = %s AND status = 1", (cliente_id_int,))
        if cursor.fetchone():
            flash("El cliente ya tiene una suscripcion activa. Debes dar de baja la suscripcion actual antes de crear otra.", "error")
            return redirect(url_for('suscripciones_form'))

        # revisa que el plan este activo
        cursor.execute("SELECT id, duration_days FROM membership WHERE id = %s AND is_active = 1", (membresia_id_int,))
        plan = cursor.fetchone()

        if not plan or plan['duration_days'] <= 0:
            flash("El plan seleccionado no es valido.", "error")
            return redirect(url_for('suscripciones_form'))

        # calcular la fecha fin segun duracion del plan
        end_date = fecha_inicio + timedelta(days=plan['duration_days'])
        if end_date <= fecha_inicio:
            flash("La fecha de fin debe ser posterior a la fecha de inicio.", "error")
            return redirect(url_for('suscripciones_form'))

        # guardar el contrato en la base de datos
        cursor.execute(
            """
            INSERT INTO contract (client_id, membership_id, start_date, end_date, status, created_at) 
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (cliente_id_int, membresia_id_int, fecha_inicio, end_date, int(estado))
        )
        
        conexion.commit()
        flash("Suscripcion registrada correctamente!", "success")

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR MYSQL: {e} ---")
        flash(f"Error al registrar la suscripcion: {e}", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('suscripciones_form'))


# recupera datos de una suscripcion para editar
@app.route('/suscripciones/editar/<int:id>', methods=['GET'])
def suscripciones_editar(id):
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        # obtener la suscripcion a editar
        cursor.execute("""
            SELECT 
                c.id, 
                c.client_id, 
                c.membership_id, 
                c.start_date, 
                c.end_date, 
                c.status
            FROM contract c
            WHERE c.id = %s
        """, (id,))
        suscripcion = cursor.fetchone()

        if not suscripcion:
            flash("La suscripcion que intentas editar no existe.", "error")
            return redirect(url_for('suscripciones_form'))

        # obtener lista de clientes activos
        cursor.execute("""
            SELECT id, CONCAT(name, ' ', lastname) AS nombre_completo 
            FROM client 
            WHERE is_active = 1
        """)
        lista_clientes = cursor.fetchall()

        # obtener lista de planes activos
        cursor.execute("""
            SELECT id, name AS nombre, price AS precio, duration_days AS duracion 
            FROM membership 
            WHERE is_active = 1
        """)
        lista_planes = cursor.fetchall()

        # obtener el historial completo
        cursor.execute("""
            SELECT 
                c.id,
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre, 
                m.name AS plan_nombre,
                c.start_date AS fecha_inicio,
                c.end_date AS fecha_fin,
                c.status AS estado
            FROM contract c
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN membership m ON c.membership_id = m.id
            ORDER BY c.id DESC
        """)
        lista_suscripciones = cursor.fetchall()

        return render_template(
            'suscripciones_form.html', 
            lista_clientes=lista_clientes, 
            lista_planes=lista_planes, 
            lista_suscripciones=lista_suscripciones,
            suscripcion_editar=suscripcion
        )

    except Exception as e:
        print(f"--- ERROR MYSQL AL EDITAR SUSCRIPCION: {e} ---")
        flash(f"Error al cargar la suscripcion para editar: {e}", "error")
        return redirect(url_for('suscripciones_form'))

    finally:
        cursor.close()
        conexion.close()


# actualiza los parametros de un contrato en la base de datos
@app.route('/suscripciones/actualizar/<int:id>', methods=['POST'])
def suscripciones_actualizar(id):
    cliente_id = request.form.get('cliente_id', '').strip()
    membresia_id = request.form.get('membresia_id', '').strip()
    fecha_inicio_str = request.form.get('fecha_inicio', '').strip()
    estado = request.form.get('estado', '').strip()

    # validacion de campos vacios
    if not all([cliente_id, membresia_id, fecha_inicio_str, estado]):
        flash("Todos los campos son obligatorios.", "error")
        return redirect(url_for('suscripciones_editar', id=id))

    if estado not in ('0', '1'):
        flash("El estado seleccionado no es valido.", "error")
        return redirect(url_for('suscripciones_editar', id=id))

    try:
        cliente_id_int = int(cliente_id)
        membresia_id_int = int(membresia_id)
        if cliente_id_int <= 0 or membresia_id_int <= 0:
            raise ValueError
    except ValueError:
        flash("Cliente y plan deben seleccionarse correctamente.", "error")
        return redirect(url_for('suscripciones_editar', id=id))

    try:
        fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d').date()
    except ValueError:
        flash("El formato de fecha ingresado no es valido.", "error")
        return redirect(url_for('suscripciones_editar', id=id))

    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        # validar cliente activo
        cursor.execute("SELECT id FROM client WHERE id = %s AND is_active = 1", (cliente_id_int,))
        if not cursor.fetchone():
            flash("El cliente seleccionado no existe o no esta activo.", "error")
            return redirect(url_for('suscripciones_editar', id=id))

        # validar plan activo
        cursor.execute("SELECT id, duration_days FROM membership WHERE id = %s AND is_active = 1", (membresia_id_int,))
        plan = cursor.fetchone()
        if not plan or plan['duration_days'] <= 0:
            flash("El plan seleccionado no es valido.", "error")
            return redirect(url_for('suscripciones_editar', id=id))

        # calcular la fecha fin
        end_date = fecha_inicio + timedelta(days=plan['duration_days'])
        if end_date <= fecha_inicio:
            flash("La fecha de fin debe ser posterior a la fecha de inicio.", "error")
            return redirect(url_for('suscripciones_editar', id=id))

        # actualizar contrato
        cursor.execute(
            """
            UPDATE contract
            SET client_id = %s,
                membership_id = %s,
                start_date = %s,
                end_date = %s,
                status = %s
            WHERE id = %s
            """,
            (cliente_id_int, membresia_id_int, fecha_inicio, end_date, int(estado), id)
        )
        conexion.commit()
        flash("Suscripcion actualizada correctamente.", "success")
        return redirect(url_for('suscripciones_form'))

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR MYSQL AL ACTUALIZAR SUSCRIPCION: {e} ---")
        flash("No se pudo actualizar la suscripcion. Intenta de nuevo.", "error")
        return redirect(url_for('suscripciones_editar', id=id))

    finally:
        cursor.close()
        conexion.close()


# desactiva una suscripcion cambiando su estado a 0
@app.route('/suscripciones/baja/<int:id>', methods=['POST'])
def suscripciones_baja(id):
    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        # revisar si existe
        cursor.execute("SELECT status FROM contract WHERE id = %s", (id,))
        suscripcion = cursor.fetchone()
        if not suscripcion:
            flash("La suscripcion que intentas dar de baja no existe.", "error")
            return redirect(url_for('suscripciones_form'))

        # si ya esta inactiva
        if suscripcion[0] == 0:
            flash("La suscripcion ya esta inactiva.", "info")
            return redirect(url_for('suscripciones_form'))

        # cambiar el estado a inactivo
        cursor.execute("UPDATE contract SET status = 0 WHERE id = %s", (id,))
        conexion.commit()
        flash("Suscripcion dada de baja correctamente.", "success")

    except Exception as e:
        conexion.rollback()
        flash("No se pudo desactivar la suscripcion debido a un error del servidor.", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('suscripciones_form'))


# borra un registro de contrato
@app.route('/suscripciones/eliminar/<int:id>', methods=['POST'])
def suscripciones_eliminar(id):
    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        cursor.execute("SELECT id FROM contract WHERE id = %s", (id,))
        if not cursor.fetchone():
            flash("La suscripcion que intentas eliminar no existe.", "error")
            return redirect(url_for('suscripciones_form'))

        cursor.execute("DELETE FROM contract WHERE id = %s", (id,))
        conexion.commit()
        flash("Suscripcion eliminada con exito.", "success")

    except Exception as e:
        conexion.rollback()
        flash("No se pudo eliminar la suscripcion debido a un error del servidor.", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('suscripciones_form'))


# --- crud pagos ---------------------------------------------------------------------
# muestra la lista de pagos, contratos activos e historial
@app.route('/pagos', methods=['GET'])
def pagos_form():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)
    
    try:
        # inner join para traer datos de contract, client y membership en el combo box
        cursor.execute("""
            SELECT 
                c.id, 
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre, 
                m.name AS plan_nombre,
                m.price AS plan_precio
            FROM contract c
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN membership m ON c.membership_id = m.id
            WHERE c.status = 1
            ORDER BY c.id DESC
        """)
        lista_contratos = cursor.fetchall()

        # lista de operadores
        cursor.execute("""
            SELECT id, CONCAT(name, ' ', lastname) AS nombre_completo, username AS usuario 
            FROM user
            ORDER BY name ASC
        """)
        lista_usuarios = cursor.fetchall()

        # consulta de historial de pagos
        cursor.execute("""
            SELECT 
                p.id,
                p.contract_id,
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre,
                p.amount AS monto,
                p.payment_method AS metodo_pago,
                CONCAT(u.name, ' ', u.lastname) AS operador_nombre,
                p.payment_date AS fecha
            FROM payment p
            INNER JOIN contract c ON p.contract_id = c.id
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN user u ON p.user_id = u.id
            ORDER BY p.payment_date DESC, p.id DESC
        """)
        lista_pagos = cursor.fetchall()

        return render_template(
            'pagos_form.html', 
            lista_contratos=lista_contratos, 
            lista_usuarios=lista_usuarios, 
            lista_pagos=lista_pagos,
            pago_editar=None
        )

    except Exception as e:
        print(f"--- ERROR AL CARGAR PAGOS: {e} ---")
        flash(f"Error al cargar modulo de pagos: {e}", "error")
        return render_template('pagos_form.html', lista_contratos=[], lista_usuarios=[], lista_pagos=[], pago_editar=None)
        
    finally:
        cursor.close()
        conexion.close()


# registra un pago asociado a un contrato
@app.route('/pagos/guardar', methods=['POST'])
def pagos_guardar():
    contrato_id = request.form.get('contrato_id', '').strip()
    usuario_id = request.form.get('usuario_id', '').strip()
    monto_str = request.form.get('monto', '').strip()
    metodo_pago = request.form.get('metodo_pago', '').strip()

    if not all([contrato_id, usuario_id, monto_str, metodo_pago]):
        flash("Todos los campos del pago son obligatorios.", "error")
        return redirect(url_for('pagos_form'))

    try:
        monto = float(monto_str)
        if monto <= 0:
            flash("El monto del pago debe ser un valor superior a cero.", "error")
            return redirect(url_for('pagos_form'))
    except ValueError:
        flash("El monto introducido debe ser un valor numerico valido.", "error")
        return redirect(url_for('pagos_form'))

    try:
        contrato_id_int = int(contrato_id)
        usuario_id_int = int(usuario_id)
    except ValueError:
        flash("Seleccion de contrato u operador no valida.", "error")
        return redirect(url_for('pagos_form'))

    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        # comprueba existencia de contrato y usuario operador
        cursor.execute("SELECT id FROM contract WHERE id = %s", (contrato_id_int,))
        if not cursor.fetchone():
            flash("El contrato seleccionado no existe.", "error")
            return redirect(url_for('pagos_form'))

        cursor.execute("SELECT id FROM user WHERE id = %s", (usuario_id_int,))
        if not cursor.fetchone():
            flash("El usuario operador seleccionado no existe.", "error")
            return redirect(url_for('pagos_form'))

        # validar si el contrato ya tiene un pago
        cursor.execute("SELECT id FROM payment WHERE contract_id = %s", (contrato_id_int,))
        if cursor.fetchone():
            flash("Este contrato ya cuenta con un pago registrado.", "error")
            return redirect(url_for('pagos_form'))

        # insertar pago
        cursor.execute(
            """
            INSERT INTO payment (contract_id, user_id, amount, payment_method, payment_date)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (contrato_id_int, usuario_id_int, monto, metodo_pago)
        )
        conexion.commit()
        flash("Pago registrado con exito!", "success")

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR MYSQL PAGOS: {e} ---")
        flash("Ocurrio un error en la base de datos al guardar el pago.", "error")

    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('pagos_form'))


# recupera un pago especifico para su edicion
@app.route('/pagos/editar/<int:id>', methods=['GET'])
def pagos_editar(id):
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        cursor.execute("SELECT id, contract_id, user_id, amount, payment_method FROM payment WHERE id = %s", (id,))
        pago = cursor.fetchone()

        if not pago:
            flash("El pago a editar no existe.", "error")
            return redirect(url_for('pagos_form'))

        # cargar contratos
        cursor.execute("""
            SELECT 
                c.id, 
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre, 
                m.name AS plan_nombre,
                m.price AS plan_precio
            FROM contract c
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN membership m ON c.membership_id = m.id
            ORDER BY c.id DESC
        """)
        lista_contratos = cursor.fetchall()

        # cargar operadores
        cursor.execute("SELECT id, CONCAT(name, ' ', lastname) AS nombre_completo, username AS usuario FROM user ORDER BY name ASC")
        lista_usuarios = cursor.fetchall()

        # cargar historial
        cursor.execute("""
            SELECT 
                p.id,
                p.contract_id,
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre,
                p.amount AS monto,
                p.payment_method AS metodo_pago,
                CONCAT(u.name, ' ', u.lastname) AS operador_nombre,
                p.payment_date AS fecha
            FROM payment p
            INNER JOIN contract c ON p.contract_id = c.id
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN user u ON p.user_id = u.id
            ORDER BY p.payment_date DESC, p.id DESC
        """)
        lista_pagos = cursor.fetchall()

        return render_template(
            'pagos_form.html',
            lista_contratos=lista_contratos,
            lista_usuarios=lista_usuarios,
            lista_pagos=lista_pagos,
            pago_editar=pago
        )

    except Exception as e:
        print(f"--- ERROR AL EDITAR PAGO: {e} ---")
        flash("Error al obtener la informacion del pago.", "error")
        return redirect(url_for('pagos_form'))

    finally:
        cursor.close()
        conexion.close()


# actualiza la informacion de un pago
@app.route('/pagos/actualizar/<int:id>', methods=['POST'])
def pagos_actualizar(id):
    contrato_id = request.form.get('contrato_id', '').strip()
    usuario_id = request.form.get('usuario_id', '').strip()
    monto_str = request.form.get('monto', '').strip()
    metodo_pago = request.form.get('metodo_pago', '').strip()

    if not all([contrato_id, usuario_id, monto_str, metodo_pago]):
        flash("Todos los campos del pago son obligatorios.", "error")
        return redirect(url_for('pagos_editar', id=id))

    try:
        monto = float(monto_str)
        if monto <= 0:
            flash("El monto del pago debe ser mayor a cero.", "error")
            return redirect(url_for('pagos_editar', id=id))
    except ValueError:
        flash("Monto no valido.", "error")
        return redirect(url_for('pagos_editar', id=id))

    conexion = get_connection()
    cursor = conexion.cursor()

    try:
        cursor.execute(
            """
            UPDATE payment
            SET contract_id = %s, user_id = %s, amount = %s, payment_method = %s
            WHERE id = %s
            """,
            (int(contrato_id), int(usuario_id), monto, metodo_pago, id)
        )
        conexion.commit()
        flash("Pago actualizado correctamente.", "success")
        return redirect(url_for('pagos_form'))

    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR MYSQL ACTUALIZAR PAGO: {e} ---")
        flash("Ocurrio un error al actualizar el registro de pago.", "error")
        return redirect(url_for('pagos_editar', id=id))

    finally:
        cursor.close()
        conexion.close()


# elimina un registro de pago
@app.route('/pagos/eliminar/<int:id>', methods=['POST'])
def pagos_eliminar(id):
    conexion = get_connection()
    cursor = conexion.cursor()
    cursor.execute("SELECT id FROM payment WHERE id = %s", (id,))
    if not cursor.fetchone():
        flash("El registro de pago que intentas eliminar no existe.", "error")
        return redirect(url_for('pagos_form'))
    try:
        cursor.execute("DELETE FROM payment WHERE id = %s", (id,))
        conexion.commit()
        flash("Registro de pago eliminado con exito.", "success")
    except Exception as e:
        conexion.rollback()
        print(f"--- ERROR ELIMINAR PAGO: {e} ---")
        flash("No se pudo eliminar el registro de pago.", "error")
    finally:
        cursor.close()
        conexion.close()

    return redirect(url_for('pagos_form'))


# --- reporte ---
# genera el reporte consolidado de auditoria e ingresos relacionando contratos, clientes, planes y pagos
@app.route('/reporte', methods=['GET'])
def reporte_auditoria_ingresos():
    conexion = get_connection()
    cursor = conexion.cursor(dictionary=True)

    try:
        # consulta sql consolidando contract, client, membership, payment y user
        query = """
            SELECT 
                CONCAT(cl.name, ' ', cl.lastname) AS cliente_nombre,
                m.name AS plan_nombre,
                c.start_date AS fecha_inicio,
                c.end_date AS fecha_vencimiento,
                CASE 
                    WHEN c.status = 1 THEN 'Activo'
                    ELSE 'Inactivo'
                END AS estado_contrato,
                COALESCE(p.amount, 0.00) AS monto_pago,
                COALESCE(CONCAT(u.name, ' ', u.lastname), 'Sin registro / N/A') AS empleado_nombre
            FROM contract c
            INNER JOIN client cl ON c.client_id = cl.id
            INNER JOIN membership m ON c.membership_id = m.id
            LEFT JOIN payment p ON p.contract_id = c.id
            LEFT JOIN user u ON p.user_id = u.id
            WHERE c.status = 1
            ORDER BY c.start_date DESC, p.payment_date DESC
        """
        cursor.execute(query)
        reporte_data = cursor.fetchall()

        return render_template('reporte.html', reporte=reporte_data)

    except Exception as e:
        print(f"--- ERROR EN REPORTE DE AUDITORIA: {e} ---")
        flash(f"Error al generar el reporte: {e}", "error")
        return render_template('reporte.html', reporte=[])

    finally:
        cursor.close()
        conexion.close()


# arranque del servidor de desarrollo de flask
if __name__ == "__main__":
    app.run(debug=True)