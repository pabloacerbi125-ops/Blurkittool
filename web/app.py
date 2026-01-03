# Editar nombre de modalidad
"""Flask web application for BlurkitModsTool with authentication.

Multi-user system with role-based permissions and SQLite database.
"""

import sys
import os
import subprocess
import re
from pathlib import Path
import base64
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_limiter import Limiter
from markupsafe import Markup, escape
from sqlalchemy import inspect, text
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Función para obtener la IP real incluso detrás de proxy (Render)
def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

from time import time

# Behavioral anomaly settings (simple anti-rotation):
BEHAVIOR_WINDOW_SECONDS = 900  # 15 minutos de ventana
BEHAVIOR_MAX_UNIQUE_IPS = 5    # Máximo IPs distintas por usuario en la ventana

# Tiempo máximo para considerar a un usuario como online (en segundos)
ONLINE_TIMEOUT = 180  # 3 minutos

# Intervalo mínimo entre escrituras de last_active para evitar exceso de commits
LAST_ACTIVE_MIN_UPDATE_SECONDS = 30

# ============================================================================
# AUTO GIT PULL ON STARTUP (legacy)
# ============================================================================

# NOTE: This project previously synced a SQLite database via git pulls.
# Now we use a real database (Render Postgres). Do not auto-git-pull on startup.

# Helper to locate resources when packaged with PyInstaller
def resource_path(relative_path):
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).resolve().parent
    return base / relative_path

# Make sure web module can import core
sys.path.insert(0, str(Path(__file__).resolve().parent))

from models import db, User, Mod, Modalidad, Regla
from auth import login_required, roles_required, mod_required, smod_required, admin_required
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_mc_log_utils import analyze_log_lines
from flask import jsonify
from security_middleware import init_blocker

# Flask app with proper paths
app = Flask(__name__)

# Respect reverse-proxy headers on Render (X-Forwarded-For / X-Forwarded-Proto)
# so rate limiting and redirects use the real client IP/protocol.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


_modalidad_orden_ready = False
_regla_orden_ready = False
_regla_ejemplo_ready = False
_login_attempts_ready = False
_users_2fa_ready = False
_users_last_active_ready = False


def _twofa_role_allowed(user) -> bool:
    """Only allow 2FA for higher ranks.

    Allowed (per rank UI): Founder/Owner/Admin/Manager/Smod.
    In code terms this maps to the role groups: admin + smod.
    """
    try:
        return bool(user) and bool(getattr(user, 'has_role', None)) and user.has_role('admin', 'smod')
    except Exception:
        return False


def _twofa_disable_for_user(user) -> None:
    """Best-effort: turn off 2FA for a user (used when role is not allowed)."""
    try:
        if not user:
            return
        if not getattr(user, 'twofa_enabled', False) and not getattr(user, 'twofa_secret', None):
            return
        user.twofa_enabled = False
        user.twofa_secret = None
        user.twofa_confirmed_at = None
        db.session.commit()
    except Exception as exc:
        print(f"[2FA] Warning: could not auto-disable 2FA: {exc}")
        try:
            db.session.rollback()
        except Exception:
            pass


def ensure_users_2fa_columns():
    """Idempotent runtime migration for 2FA columns on users table."""
    global _users_2fa_ready
    if _users_2fa_ready:
        return
    try:
        dialect = getattr(getattr(db, 'engine', None), 'dialect', None)
        dialect_name = getattr(dialect, 'name', '') or ''
        is_postgres = dialect_name.startswith('postgres')
        insp = inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('users')}
        with db.engine.begin() as conn:
            if 'twofa_enabled' not in cols:
                if is_postgres:
                    conn.execute(text("ALTER TABLE users ADD COLUMN twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
                else:
                    conn.execute(text("ALTER TABLE users ADD COLUMN twofa_enabled BOOLEAN NOT NULL DEFAULT 0"))
            if 'twofa_secret' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN twofa_secret VARCHAR(64)"))
            if 'twofa_confirmed_at' not in cols:
                if is_postgres:
                    conn.execute(text("ALTER TABLE users ADD COLUMN twofa_confirmed_at TIMESTAMP"))
                else:
                    conn.execute(text("ALTER TABLE users ADD COLUMN twofa_confirmed_at DATETIME"))
        _users_2fa_ready = True
    except Exception as e:
        print(f"[MIGRATION] ensure_users_2fa_columns failed: {e}")


def ensure_users_last_active_column():
    """Idempotent runtime migration for 'last_active' column on users table.

    IMPORTANT: must run before any request touches current_user/load_user when
    the model contains the column, otherwise SELECTs can fail on older DBs.
    """
    global _users_last_active_ready
    if _users_last_active_ready:
        return

    try:
        dialect = getattr(getattr(db, 'engine', None), 'dialect', None)
        dialect_name = getattr(dialect, 'name', '') or ''
        is_postgres = dialect_name.startswith('postgres')
        insp = inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('users')}
        if 'last_active' in cols:
            _users_last_active_ready = True
            return

        with db.engine.begin() as conn:
            if is_postgres:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_active TIMESTAMP"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_active DATETIME"))

        _users_last_active_ready = True
    except Exception as e:
        print(f"[MIGRATION] ensure_users_last_active_column failed: {e}")


def _twofa_issuer_name() -> str:
    return os.environ.get('TWOFA_ISSUER', 'BlurkitTool')


def _twofa_qr_data_uri(otpauth_url: str) -> str:
    """Generate PNG QR as data URI to embed in HTML."""
    import qrcode

    img = qrcode.make(otpauth_url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/png;base64,{b64}"


def ensure_modalidad_orden_column():
    """Ensure the 'orden' column exists on 'modalidades' table.

    This project doesn't use Alembic; so we run a small, idempotent migration at
    runtime to support drag-and-drop ordering.
    """
    global _modalidad_orden_ready
    if _modalidad_orden_ready:
        return

    try:
        inspector = inspect(db.engine)
        if 'modalidades' not in inspector.get_table_names():
            _modalidad_orden_ready = True
            return

        column_names = {c['name'] for c in inspector.get_columns('modalidades')}
        if 'orden' not in column_names:
            db.session.execute(text('ALTER TABLE modalidades ADD COLUMN orden INTEGER NOT NULL DEFAULT 0'))
            db.session.commit()

            modalidades_init = Modalidad.query.order_by(Modalidad.nombre.asc()).all()
            for idx, modalidad in enumerate(modalidades_init, start=1):
                modalidad.orden = idx
            db.session.commit()

        _modalidad_orden_ready = True
    except Exception as exc:
        print(f"[Modalidad orden] Warning: could not ensure column: {exc}", flush=True)
        _modalidad_orden_ready = True


def ensure_regla_orden_column():
    """Ensure the 'orden' column exists on 'reglas' table.

    Like Modalidad ordering, this project doesn't use Alembic; so we run an
    idempotent migration at runtime.
    """
    global _regla_orden_ready
    if _regla_orden_ready:
        return

    try:
        inspector = inspect(db.engine)
        if 'reglas' not in inspector.get_table_names():
            _regla_orden_ready = True
            return

        column_names = {c['name'] for c in inspector.get_columns('reglas')}
        if 'orden' not in column_names:
            db.session.execute(text('ALTER TABLE reglas ADD COLUMN orden INTEGER NOT NULL DEFAULT 0'))
            db.session.commit()

            # Initialize per-modalidad order based on insertion (id)
            modalidad_ids = [row[0] for row in db.session.query(Regla.modalidad_id).distinct().all()]
            for modalidad_id in modalidad_ids:
                reglas_init = (
                    Regla.query.filter_by(modalidad_id=modalidad_id)
                    .order_by(Regla.id.asc())
                    .all()
                )
                for idx, regla in enumerate(reglas_init, start=1):
                    regla.orden = idx
            db.session.commit()

        _regla_orden_ready = True
    except Exception as exc:
        print(f"[Regla orden] Warning: could not ensure column: {exc}", flush=True)
        _regla_orden_ready = True


def ensure_regla_ejemplo_column():
    """Ensure the optional 'ejemplo' column exists on 'reglas' table.

    This project doesn't use Alembic; so we run an idempotent migration at runtime.
    """
    global _regla_ejemplo_ready
    if _regla_ejemplo_ready:
        return

    try:
        inspector = inspect(db.engine)
        if 'reglas' not in inspector.get_table_names():
            _regla_ejemplo_ready = True
            return

        column_names = {c['name'] for c in inspector.get_columns('reglas')}
        if 'ejemplo' not in column_names:
            db.session.execute(text('ALTER TABLE reglas ADD COLUMN ejemplo TEXT'))
            db.session.commit()

        _regla_ejemplo_ready = True
    except Exception as exc:
        print(f"[Regla ejemplo] Warning: could not ensure column: {exc}", flush=True)
        _regla_ejemplo_ready = True


def ensure_login_attempts_columns():
    """Ensure incremental-lockout columns exist on 'login_attempts'.

    Adds:
    - block_count (int)
    - blocked_until (datetime)

    This project doesn't use Alembic; so we run an idempotent migration at runtime.
    """
    global _login_attempts_ready
    if _login_attempts_ready:
        return

    try:
        inspector = inspect(db.engine)
        if 'login_attempts' not in inspector.get_table_names():
            _login_attempts_ready = True
            return

        column_names = {c['name'] for c in inspector.get_columns('login_attempts')}
        if 'block_count' not in column_names:
            db.session.execute(text('ALTER TABLE login_attempts ADD COLUMN block_count INTEGER NOT NULL DEFAULT 0'))
            db.session.commit()

        column_names = {c['name'] for c in inspector.get_columns('login_attempts')}
        if 'blocked_until' not in column_names:
            dialect = getattr(getattr(db, 'engine', None), 'dialect', None)
            dialect_name = getattr(dialect, 'name', '') or ''
            is_postgres = dialect_name.startswith('postgres')
            if is_postgres:
                db.session.execute(text('ALTER TABLE login_attempts ADD COLUMN blocked_until TIMESTAMP'))
            else:
                db.session.execute(text('ALTER TABLE login_attempts ADD COLUMN blocked_until DATETIME'))
            db.session.commit()

        _login_attempts_ready = True
    except Exception as exc:
        print(f"[LoginAttempt] Warning: could not ensure columns: {exc}", flush=True)
        _login_attempts_ready = True


@app.template_filter('highlight_prohibido')
def highlight_prohibido(text):
    """Highlight the word 'PROHIBIDO' in rendered text.

    Escapes input first to prevent XSS, then wraps case-insensitive whole-word
    matches in a span so CSS can style it.
    """
    if text is None:
        return ''

    raw_text = str(text)
    # Normaliza saltos de línea reales y también secuencias literales "\\n" / "\\r\\n"
    # que pueden venir almacenadas en la BD como texto.
    normalized = (
        raw_text
        .replace('\\r\\n', '\n')
        .replace('\\n', '\n')
        .replace('\r\n', '\n')
    )

    escaped = escape(normalized)

    def repl(match):
        return f'<span class="prohibido-word">{match.group(0)}</span>'


    highlighted = re.sub(r'\bPROHIBIDO\b', repl, str(escaped), flags=re.IGNORECASE)
    highlighted = highlighted.replace('\n', '<br>')
    return Markup(highlighted)

@app.route('/editar_modalidad/<int:modalidad_id>', methods=['POST'])
@login_required
@smod_required
def editar_modalidad(modalidad_id):
    modalidad = Modalidad.query.get_or_404(modalidad_id)
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
    nuevo_nombre = request.form.get('nuevo_nombre', '').strip()
    if not nuevo_nombre:
        flash('El nombre no puede estar vacío.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
    if Modalidad.query.filter(Modalidad.nombre == nuevo_nombre, Modalidad.id != modalidad_id).first():
        flash('Ya existe otra modalidad con ese nombre.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
    modalidad.nombre = nuevo_nombre
    db.session.commit()
    flash('Nombre de modalidad actualizado.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
@app.route('/editar_regla/<int:regla_id>', methods=['POST'])
@login_required
@smod_required
def editar_regla(regla_id):
    ensure_regla_orden_column()
    ensure_regla_ejemplo_column()
    regla = Regla.query.get_or_404(regla_id)

    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))
    nueva_desc = request.form.get('nueva_descripcion', '').strip()
    nuevo_orden_raw = request.form.get('nuevo_orden', '').strip()
    if not nueva_desc:
        flash('La descripción no puede estar vacía.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))

    nuevo_orden = None
    if nuevo_orden_raw:
        try:
            nuevo_orden = int(nuevo_orden_raw)
        except ValueError:
            flash('El número de regla debe ser un entero válido.', 'danger')
            return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))
        if nuevo_orden < 1:
            flash('El número de regla debe ser mayor o igual a 1.', 'danger')
            return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))

    regla.descripcion = nueva_desc
    if nuevo_orden is not None:
        regla.orden = nuevo_orden
    db.session.commit()
    flash('Regla editada correctamente.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))


@app.route('/editar_ejemplo_regla/<int:regla_id>', methods=['POST'])
@login_required
@smod_required
def editar_ejemplo_regla(regla_id):
    ensure_regla_orden_column()
    ensure_regla_ejemplo_column()
    regla = Regla.query.get_or_404(regla_id)

    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))

    nuevo_ejemplo = request.form.get('nuevo_ejemplo', '')
    # Permitir vaciar el ejemplo
    nuevo_ejemplo = (nuevo_ejemplo or '').strip()
    regla.ejemplo = nuevo_ejemplo if nuevo_ejemplo else None

    db.session.commit()
    flash('Ejemplo actualizado correctamente.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=regla.modalidad_id))
limiter = Limiter(
    key_func=get_real_ip,
    app=app,
    default_limits=[os.environ.get('DEFAULT_RATELIMIT', '200 per minute')],
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
    headers_enabled=True,
)

# Inicializa el sistema de bloqueo global anti-bot
# Si usas Redis para limiter, pásalo aquí también: init_blocker(app, redis_client)
blocker = init_blocker(app)

_secret_key = os.environ.get('SECRET_KEY')
if os.environ.get('FLASK_ENV') == 'production' and not _secret_key:
    raise RuntimeError('SECRET_KEY is required in production.')
app.config['SECRET_KEY'] = _secret_key or 'dev-secret-key-change-in-production'

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.route('/menu')
@login_required
@limiter.limit('30 per minute')
def menu():
    try:
        total_mods = Mod.query.count()
        prohibidos_count = Mod.query.filter_by(status='prohibido').count()
        permitidos_count = Mod.query.filter_by(status='permitido').count()
    except Exception as e:
        total_mods = prohibidos_count = permitidos_count = 0
        flash(f'Error al consultar mods: {e}', 'danger')
    stats = {
        'total': total_mods,
        'prohibidos': prohibidos_count,
        'permitidos': permitidos_count
    }
    return render_template('menu.html', stats=stats)

# ===================== API: Análisis de logs Minecraft =====================
@app.route('/api/analyze_log', methods=['POST'])
@login_required
@limiter.limit('15 per minute')
def api_analyze_log():
    """API endpoint para analizar logs de Minecraft. Ahora requiere login (solo staff)."""
    if request.content_length and request.content_length > MAX_LOG_UPLOAD_BYTES:
        return jsonify({'error': 'Contenido demasiado grande'}), 413
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        f = request.files.get('logfile')
        if not f or f.filename == '':
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        filename = secure_filename(f.filename or '')
        ext = Path(filename).suffix.lower()
        if ext not in ('.log', '.txt'):
            return jsonify({'error': 'Formato no válido. Solo .log o .txt'}), 400
        try:
            content = _read_text_filestorage_limited(f, MAX_LOG_UPLOAD_BYTES)
        except ValueError:
            return jsonify({'error': 'Archivo demasiado grande'}), 413
        log_lines = content.splitlines()
    else:
        log_text = request.get_data(as_text=True)
        if not log_text.strip():
            return jsonify({'error': 'No se envió contenido'}), 400
        if len(log_text) > MAX_LOG_PASTE_CHARS:
            return jsonify({'error': 'Contenido demasiado grande'}), 413
        log_lines = log_text.splitlines()
    result = analyze_log_lines(log_lines)
    return jsonify(result)
from models import LoginAttempt
import hmac
import secrets
app.config['PERMANENT_SESSION_LIFETIME'] = 600  # 10 minutos
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Hard limits for log payloads (upload + paste). Keep these reasonably low to
# prevent memory/CPU spikes and oversized cookie sessions.
MAX_LOG_UPLOAD_BYTES = int(os.environ.get('MAX_LOG_UPLOAD_BYTES', str(2 * 1024 * 1024)))  # 2MB
MAX_LOG_PASTE_CHARS = int(os.environ.get('MAX_LOG_PASTE_CHARS', str(200_000)))  # 200k chars


def _normalize_analysis_result(resultado: dict, log_lines: list[str]) -> dict:
    """Normalize analysis result to the structure expected by analysis.html.

    Target structure:
      mods_permitidos, mods_prohibidos, mods_desconocidos, dependencias,
      total, total_mods, plus optional player/mc_version.

    If resultado already matches, we keep it and only compute totals.
    """
    if not isinstance(resultado, dict):
        return {'error': 'resultado_invalid'}

    # If the analyzer already returns the final structure, just compute totals.
    if all(k in resultado for k in ['mods_permitidos', 'mods_prohibidos', 'mods_desconocidos', 'dependencias']):
        resultado['total'] = (
            len(resultado.get('mods_permitidos') or [])
            + len(resultado.get('mods_prohibidos') or [])
            + len(resultado.get('mods_desconocidos') or [])
            + len(resultado.get('dependencias') or [])
        )
        resultado['total_mods'] = (
            len(resultado.get('mods_permitidos') or [])
            + len(resultado.get('mods_prohibidos') or [])
            + len(resultado.get('mods_desconocidos') or [])
        )
        return resultado

    # Otherwise, convert from legacy structure: {mods: [...], dependencies: [...]}
    mods = resultado.get('mods') or []
    dependencies = resultado.get('dependencies') or []

    mods_prohibidos = []
    mods_permitidos = []
    mods_desconocidos = []

    all_mods_db = []
    try:
        all_mods_db = list(Mod.query.all())
    except Exception:
        all_mods_db = []

    def match_mod(mod_name: str):
        mod_name_norm = (mod_name or '').lower().replace(' ', '')
        if not mod_name_norm:
            return None
        for m in all_mods_db:
            try:
                db_name = (m.name or '').lower().replace(' ', '')
                if mod_name_norm == db_name:
                    return m
                if getattr(m, 'aliases', None):
                    for alias in (m.aliases or '').split(','):
                        if mod_name_norm == alias.strip().lower().replace(' ', ''):
                            return m
            except Exception:
                continue
        return None

    for mod in mods:
        mod_name = (mod or {}).get('name', '')
        db_mod = match_mod(mod_name)
        if db_mod:
            mod_info = {**mod, 'category': db_mod.category, 'platform': db_mod.platform, 'description': db_mod.description}
            if db_mod.status == 'prohibido':
                mods_prohibidos.append(mod_info)
            elif db_mod.status == 'permitido':
                mods_permitidos.append(mod_info)
            else:
                mods_desconocidos.append(mod)
        else:
            mods_desconocidos.append(mod)

    # Dependencias (solo se listan en analysis.html; no hay columnas extra ahí)
    # Intentamos matchear igual para consistencia, pero mantenemos el listado final en resultado['dependencias'].
    dependencias = []
    for dep in dependencies:
        dep_name = (dep or {}).get('name', '')
        db_mod = match_mod(dep_name)
        if db_mod:
            dependencias.append({**dep, 'category': db_mod.category, 'platform': db_mod.platform})
        else:
            dependencias.append(dep)

    resultado['mods_prohibidos'] = mods_prohibidos
    resultado['mods_permitidos'] = mods_permitidos
    resultado['mods_desconocidos'] = mods_desconocidos
    resultado['dependencias'] = dependencias
    resultado['total'] = len(mods) + len(dependencies)
    resultado['total_mods'] = len(mods_permitidos) + len(mods_prohibidos) + len(mods_desconocidos)
    return resultado


def _analyze_log_text_unified(log_text: str) -> dict:
    """Unified analyzer used by both /upload and /analyze."""
    from core import analyze_log_with_gpt
    from analyze_mc_log_utils import extract_player
    openai_api_key = os.environ.get('OPENAI_API_KEY')
    if openai_api_key:
        resultado = analyze_log_with_gpt(log_text, openai_api_key)
        if isinstance(resultado, dict) and resultado.get('error'):
            resultado = analyze_log_lines(log_text.splitlines())
    else:
        resultado = analyze_log_lines(log_text.splitlines())

    # Ensure player is present
    if isinstance(resultado, dict) and not resultado.get('player'):
        resultado['player'] = extract_player(log_text.splitlines())

    # Normalize structure
    resultado = _normalize_analysis_result(resultado or {}, log_text.splitlines())

    # Optional debug dump
    if os.environ.get('DEBUG_IA_RAW') == '1':
        import logging
        logging.basicConfig(level=logging.INFO)
        with open('ia_raw_result.json', 'w', encoding='utf-8') as f:
            import json as _json
            f.write(_json.dumps(resultado, ensure_ascii=False, indent=2))

    return resultado


def _get_csrf_token() -> str:
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
        session.modified = True
    return token


def _validate_csrf() -> bool:
    expected = session.get('_csrf_token', '')
    # Accept token from form body or custom header for fetch requests.
    provided = request.form.get('csrf_token', '') or request.headers.get('X-CSRF-Token', '')
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)


def _read_text_filestorage_limited(file_storage, max_bytes: int) -> str:
    data = file_storage.stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError('file_too_large')
    try:
        return data.decode('utf-8', errors='replace')
    except Exception:
        return data.decode('latin-1', errors='replace')

# Database path - use absolute path
basedir = Path(__file__).resolve().parent
db_path = basedir / 'instance' / 'blurkit.db'
db_path.parent.mkdir(parents=True, exist_ok=True)

database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Render and some providers use postgres:// but SQLAlchemy expects postgresql://
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # In Render production we must NOT fall back to a local SQLite DB.
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError('DATABASE_URL is required in production. Set it to Render Internal Database URL.')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = os.environ.get('FLASK_ENV') != 'production'


@app.route('/admin/change-background', methods=['POST'])
@roles_required('smod', 'admin')
def admin_change_background():
    """Replace the public background image (minecraft-bg.jpg).

    Admin-only; used from the /menu navbar.
    """
    file = request.files.get('background')
    if not file or not file.filename:
        flash('Selecciona una imagen para cambiar el fondo.', 'danger')
        return redirect(url_for('menu'))

    filename = secure_filename(file.filename)
    ext = Path(filename).suffix.lower()
    if ext not in ('.jpg', '.jpeg'):
        flash('Formato no válido. Solo se permiten imágenes JPG/JPEG.', 'danger')
        return redirect(url_for('menu'))

    try:
        target_path = Path(app.static_folder) / 'minecraft-bg.jpg'
        file.save(target_path)
        flash('Fondo actualizado correctamente.', 'success')
    except Exception as exc:
        flash(f'Error al actualizar el fondo: {exc}', 'danger')

    return redirect(url_for('menu'))

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'info'


@app.context_processor
def inject_csrf_token():
    # Make csrf_token available in all templates (base.html heartbeat, etc.)
    return {'csrf_token': _get_csrf_token()}




@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except:
        return None


@app.before_request
def ensure_runtime_schema_before_auth():
    """Ensure required columns exist before anything touches current_user.

    This MUST run before other before_request handlers that access current_user,
    otherwise load_user() may run a SELECT for missing columns.
    """
    ensure_users_last_active_column()


@app.before_request
def restore_session_history():
    """Restore history from session to memory before each request."""
    if current_user.is_authenticated:
        user_key = current_user.username
        # Si hay historial en sesión y no en memoria, restaurarlo
        if 'logs_history' in session and user_key not in logs_history:
            logs_history[user_key] = session.get('logs_history', [])
        # Hacer sesiones permanentes
        session.permanent = True


# Solo cerrar sesión al iniciar la app (primer request tras reinicio)
logout_flag = {'done': False}

@app.before_request
def force_logout_on_render():
    # Solo forzar logout si NO estamos en login, autenticando, ni sirviendo archivos estáticos
    if os.environ.get('FLASK_ENV') == 'production' and not logout_flag['done']:
        if request.endpoint and not request.endpoint.startswith(('login', 'static', 'auth', 'admin_create_user')) and current_user.is_authenticated:
            logout_flag['done'] = True  # Mover antes del redirect para evitar doble logout
            session.clear()
            logout_user()
            flash('Por seguridad, vuelve a iniciar sesión.', 'info')
            return redirect(url_for('login'))


@app.before_request
def track_user_last_active():
    """Persist last activity in DB (multi-worker safe).

    Throttles updates to avoid committing on every request.
    """
    try:
        if not current_user.is_authenticated:
            return

        # Anti-rotación de IPs: si un usuario cambia demasiadas IP en poco tiempo, bloquear temporalmente.
        try:
            ip = get_real_ip()
            now_ts = time()
            entries = behavior_tracker.get(current_user.username, [])
            # purgar ventana
            entries = [(ip0, ts0) for (ip0, ts0) in entries if now_ts - ts0 <= BEHAVIOR_WINDOW_SECONDS]
            entries.append((ip, now_ts))
            behavior_tracker[current_user.username] = entries
            unique_ips = len({ip0 for ip0, _ in entries})
            if unique_ips > BEHAVIOR_MAX_UNIQUE_IPS:
                flash('Demasiados cambios de IP recientes. Intenta más tarde.', 'danger')
                abort(429)
        except Exception:
            pass

        ensure_users_last_active_column()

        now_utc = datetime.utcnow()
        last_active = getattr(current_user, 'last_active', None)

        if last_active is None or (now_utc - last_active).total_seconds() >= LAST_ACTIVE_MIN_UPDATE_SECONDS:
            current_user.last_active = now_utc
            db.session.commit()
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"[PRESENCE] Warning: could not update last_active: {exc}")


# ============================================================================
# PUBLIC ROUTES (No login required)
# ============================================================================

# Rate limiting - simple in-memory storage (use Redis in production)
login_attempts = {}

# Anti-rotation in-memory tracker: {username: [(ip, ts), ...]}
behavior_tracker = {}

# In-memory history cache for session support (primary storage is in Flask sessions)
# Structure: {username: [{'timestamp': str, 'filename': str, 'resultado': dict}, ...]}
logs_history = {}
MAX_HISTORY_ITEMS = 20

# ============================================================================
# GIT AUTO-SYNC FUNCTION (for Render deployment)
# ============================================================================

def auto_commit_and_push(message):
    """Legacy: git-based DB syncing.

    This project used to sync a local SQLite DB via GitHub commits.
    Now the app uses Render Postgres (DATABASE_URL), so we intentionally
    disable any git commits/pushes of database state.
    """
    print(f"[Auto-sync disabled] {message}", flush=True)
    return False


def _normalize_status(raw_status: str) -> str:
    val = (raw_status or '').strip().lower()
    if val in ('permitido', 'prohibido'):
        return val
    return 'prohibido'


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with rate limiting."""
    if current_user.is_authenticated:
        return redirect(url_for('menu'))
    
    if request.method == 'POST':
        ensure_login_attempts_columns()
        ensure_users_2fa_columns()

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = get_real_ip()
        xff = request.headers.get('X-Forwarded-For')
        print(f"[LOGIN] Intento de login desde IP real: {ip_address} (usuario: {username}) | X-Forwarded-For: {xff}")

        user = User.query.filter_by(username=username).first()


        # Verificar si la IP/usuario está bloqueada antes de validar el login
        from models import LoginAttempt
        now = datetime.now()
        attempt = LoginAttempt.query.filter_by(ip_address=ip_address, username=username).first()

        # Handle incremental lockouts: 15m, 30m, 45m... per block event.
        if attempt:
            # If lock expired, clear it but keep block_count.
            if attempt.blocked_until and now >= attempt.blocked_until:
                attempt.is_blocked = False
                attempt.blocked_until = None
                attempt.attempts = 0
                db.session.commit()

            # Active lock
            if attempt.blocked_until and now < attempt.blocked_until:
                remaining_minutes = max(1, int((attempt.blocked_until - now).total_seconds() / 60))
                flash(f'Demasiados intentos. Bloqueado por {remaining_minutes} min.', 'danger')
                return render_template('login.html'), 429

            # Legacy fallback: older rows may have is_blocked/attempts>=5 without blocked_until.
            if (attempt.is_blocked or attempt.attempts >= 5) and not attempt.blocked_until:
                legacy_until = attempt.last_attempt + timedelta(minutes=15)
                if now < legacy_until:
                    attempt.is_blocked = True
                    attempt.blocked_until = legacy_until
                    attempt.block_count = max(int(attempt.block_count or 0), 1)
                    db.session.commit()
                    remaining_minutes = max(1, int((legacy_until - now).total_seconds() / 60))
                    flash(f'Demasiados intentos. Bloqueado por {remaining_minutes} min.', 'danger')
                    return render_template('login.html'), 429
                else:
                    attempt.is_blocked = False
                    attempt.attempts = 0
                    attempt.blocked_until = None
                    db.session.commit()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Tu cuenta está desactivada. Contacta al administrador.', 'danger')
                return redirect(url_for('login'))

            # Éxito: limpiar intentos fallidos de esta IP/usuario
            from models import LoginAttempt
            try:
                attempt = LoginAttempt.query.filter_by(ip_address=ip_address, username=username).first()
                if attempt:
                    db.session.delete(attempt)
                    db.session.commit()
            except Exception as e:
                print(f"[SECURITY] Error limpiando intentos: {e}")

            # Enforce: only certain ranks can use 2FA
            if not _twofa_role_allowed(user):
                _twofa_disable_for_user(user)

            # If user has 2FA enabled, do a second step before creating session
            if _twofa_role_allowed(user) and getattr(user, 'twofa_enabled', False) and getattr(user, 'twofa_secret', None):
                session['twofa_pending_user_id'] = user.id
                session.permanent = True
                session.modified = True
                return redirect(url_for('twofa_login_verify'))

            # Update last login (store as UTC so UI can localize per viewer)
            user.last_login = datetime.utcnow()
            # Also mark as active now (used for online/offline status)
            try:
                user.last_active = user.last_login
            except Exception:
                pass
            db.session.commit()

            login_user(user, remember=True)
            flash(f'¡Bienvenido, {user.username}!', 'success')

            # Validate next parameter to prevent open redirect
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('menu'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

            # Registrar intento fallido en la base de datos
            from models import LoginAttempt
            now = datetime.now()
            try:
                attempt = LoginAttempt.query.filter_by(ip_address=ip_address, username=username).first()

                if attempt:
                    # If the last attempt was long ago (15m+), reset counter window.
                    if (now - attempt.last_attempt).total_seconds() > 900 and not attempt.blocked_until:
                        attempt.attempts = 0
                        attempt.is_blocked = False

                    # If currently blocked, don't mutate counters here.
                    if attempt.blocked_until and now < attempt.blocked_until:
                        remaining_minutes = max(1, int((attempt.blocked_until - now).total_seconds() / 60))
                        flash(f'Demasiados intentos. Bloqueado por {remaining_minutes} min.', 'danger')
                        return render_template('login.html'), 429

                    attempt.attempts = int(attempt.attempts or 0) + 1
                    attempt.last_attempt = now

                    if attempt.attempts >= 5:
                        attempt.block_count = int(attempt.block_count or 0) + 1
                        lock_minutes = 15 * attempt.block_count
                        attempt.blocked_until = now + timedelta(minutes=lock_minutes)
                        attempt.is_blocked = True

                    db.session.commit()
                else:
                    attempt = LoginAttempt(
                        ip_address=ip_address,
                        username=username,
                        attempts=1,
                        last_attempt=now,
                        is_blocked=False,
                        block_count=0,
                        blocked_until=None,
                    )
                    db.session.add(attempt)
                    db.session.commit()

            except Exception as e:
                print(f"[SECURITY] Error registrando intento fallido: {e}")

    return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """Logout current user."""
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))


# ============================================================================
# PUBLIC ROUTES (No login required)
# ============================================================================

@app.route('/')
def home():
    """Public homepage - shows mods list and rules without login."""
    all_mods = Mod.query.order_by(Mod.name).all()
    permitidos = [(idx, m.to_dict()) for idx, m in enumerate(all_mods) if m.status == 'permitido']
    prohibidos = [(idx, m.to_dict()) for idx, m in enumerate(all_mods) if m.status == 'prohibido']
    
    return render_template('home.html', permitidos=permitidos, prohibidos=prohibidos)


@app.route('/page')
def page():
    """Public page with menu buttons only."""
    return render_template('page.html')


@app.route('/modsjg')
def modsjg():
    """Lista pública de modos."""
    all_mods = Mod.query.order_by(Mod.name).all()
    filtered_mods = [m.to_dict() for m in all_mods]
    permitidos = [(idx, m) for idx, m in enumerate(filtered_mods) if m['status'] == 'permitido']
    prohibidos = [(idx, m) for idx, m in enumerate(filtered_mods) if m['status'] == 'prohibido']
    return render_template('modsjg.html', permitidos=permitidos, prohibidos=prohibidos)


@app.route('/reglas')
def reglas():
    """Public rules page - separate page for viewing rules."""
    ensure_modalidad_orden_column()
    ensure_regla_orden_column()
    ensure_regla_ejemplo_column()
    modalidades = Modalidad.query.order_by(Modalidad.orden.asc(), Modalidad.nombre.asc()).all()
    return render_template('reglas.html', modalidades=modalidades)


@app.route('/reglasadm', methods=['GET', 'POST'])
@login_required
@smod_required
def reglasadm():
    """Admin rules management - view and create modalities, and show/add rules for selected modality."""
    ensure_modalidad_orden_column()
    ensure_regla_orden_column()
    ensure_regla_ejemplo_column()
    modalidades = Modalidad.query.order_by(Modalidad.orden.asc(), Modalidad.nombre.asc()).all()
    modalidad_id = request.args.get('modalidad_id', type=int)
    modalidad_seleccionada = None
    reglas = []
    if modalidad_id:
        modalidad_seleccionada = db.session.get(Modalidad, modalidad_id)
        if modalidad_seleccionada:
            reglas = (
                Regla.query.filter_by(modalidad_id=modalidad_id)
                .order_by(Regla.orden.asc(), Regla.id.asc())
                .all()
            )

    if request.method == 'POST':
        if not _validate_csrf():
            flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
            return redirect(url_for('reglasadm', modalidad_id=modalidad_id or None))
        # Agregar modalidad
        if 'nombre' in request.form:
            nombre = request.form.get('nombre', '').strip()
            if not nombre:
                flash('El nombre de la modalidad es obligatorio.', 'danger')
                return redirect(url_for('reglasadm'))
            if Modalidad.query.filter_by(nombre=nombre).first():
                flash('Ya existe una modalidad con ese nombre.', 'danger')
                return redirect(url_for('reglasadm'))
            max_orden = db.session.query(db.func.max(Modalidad.orden)).scalar() or 0
            nueva = Modalidad(nombre=nombre, orden=int(max_orden) + 1)
            db.session.add(nueva)
            db.session.commit()
            flash('Modalidad agregada.', 'success')
            return redirect(url_for('reglasadm'))
        # Agregar regla
        elif 'descripcion_regla' in request.form and modalidad_id:
            descripcion = request.form.get('descripcion_regla', '').strip()
            if not descripcion:
                flash('La descripción de la regla es obligatoria.', 'danger')
                return redirect(url_for('reglasadm', modalidad_id=modalidad_id))

            max_orden = (
                db.session.query(db.func.max(Regla.orden))
                .filter(Regla.modalidad_id == modalidad_id)
                .scalar()
                or 0
            )
            nueva_regla = Regla(descripcion=descripcion, modalidad_id=modalidad_id, orden=int(max_orden) + 1)
            db.session.add(nueva_regla)
            db.session.commit()
            flash('Regla agregada.', 'success')
            return redirect(url_for('reglasadm', modalidad_id=modalidad_id))

    return render_template('reglasadm.html', modalidades=modalidades, modalidad_seleccionada=modalidad_seleccionada, reglas=reglas)


@app.route('/reordenar_modalidades', methods=['POST'])
@login_required
@smod_required
def reordenar_modalidades():
    """Persist drag-and-drop ordering for modalidades."""
    ensure_modalidad_orden_column()

    if not _validate_csrf():
        return jsonify({'ok': False, 'error': 'csrf'}), 400

    data = request.get_json(silent=True) or {}
    order = data.get('order')
    if not isinstance(order, list):
        return jsonify({'ok': False, 'error': 'Formato inválido'}), 400

    ids = []
    for raw_id in order:
        try:
            ids.append(int(raw_id))
        except (TypeError, ValueError):
            continue

    if not ids:
        return jsonify({'ok': False, 'error': 'Lista vacía'}), 400

    for idx, modalidad_id in enumerate(ids, start=1):
        modalidad = db.session.get(Modalidad, modalidad_id)
        if modalidad:
            modalidad.orden = idx

    db.session.commit()
    return jsonify({'ok': True})



# Editar nota de modalidad
@app.route('/editar_nota_modalidad/<int:modalidad_id>', methods=['POST'])
@login_required
@smod_required
def editar_nota_modalidad(modalidad_id):
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
    modalidad = Modalidad.query.get_or_404(modalidad_id)
    nueva_nota = request.form.get('nueva_nota', '').strip()
    modalidad.nota = nueva_nota
    db.session.commit()
    flash('Nota de la modalidad actualizada.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=modalidad_id))

@app.route('/eliminar_modalidad/<int:modalidad_id>', methods=['POST'])
@login_required
@smod_required
def eliminar_modalidad(modalidad_id):
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm', modalidad_id=modalidad_id))
    modalidad = Modalidad.query.get_or_404(modalidad_id)
    db.session.delete(modalidad)
    db.session.commit()
    flash('Modalidad eliminada correctamente.', 'success')
    return redirect(url_for('reglasadm'))


@app.route('/eliminar_regla/<int:regla_id>', methods=['POST'])
@login_required
@smod_required
def eliminar_regla(regla_id):
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('reglasadm'))
    ensure_regla_orden_column()
    ensure_regla_ejemplo_column()
    regla = Regla.query.get_or_404(regla_id)
    modalidad_id = regla.modalidad_id
    db.session.delete(regla)
    db.session.commit()
    flash('Regla eliminada correctamente.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=modalidad_id))

# ============================================================================
# AUTHENTICATED ROUTES (Login required, all roles can access)
# ============================================================================

@app.route('/mods')
@login_required
def index():
    """List all mods - viewable by all roles."""
    search_term = request.args.get('search', '').strip()
    
    if search_term:
        # Filtrar mods por nombre o alias
        mods = Mod.query.filter(
            db.or_(
                Mod.name.ilike(f'%{search_term}%'),
                Mod.aliases.ilike(f'%{search_term}%')
            )
        ).order_by(Mod.name).all()
    else:
        mods = Mod.query.order_by(Mod.name).all()
    
    prohibidos = [(m.id, m) for m in mods if m.status == 'prohibido']
    permitidos = [(m.id, m) for m in mods if m.status == 'permitido']
    return render_template('index.html', prohibidos=prohibidos, permitidos=permitidos, search_term=search_term)


@app.route('/api/search', methods=['POST'])
@login_required
@limiter.limit('30 per minute')
def api_search():
    """API endpoint para búsqueda en tiempo real (AJAX) - requiere autenticación."""
    data = request.get_json(silent=True) or {}
    term = (data.get('term', '') or '').lower().strip()
    
    if not term:
        return jsonify({'resultado': []})
    
    # Search in name and aliases
    mods = Mod.query.filter(
        db.or_(
            Mod.name.ilike(f'%{term}%'),
            Mod.aliases.ilike(f'%{term}%')
        )
    ).limit(20).all()
    
    resultado = [m.to_dict() for m in mods]
    return jsonify({'resultado': resultado})


@app.route('/api/search-public', methods=['POST'])
@limiter.limit('60 per minute')
def api_search_public():
    """API endpoint para búsqueda pública en tiempo real (AJAX) - sin autenticación."""
    data = request.get_json(silent=True) or {}
    term = (data.get('term', '') or '').lower().strip()
    
    if not term:
        return jsonify({'resultado': []})
    
    # Search in name and aliases
    mods = Mod.query.filter(
        db.or_(
            Mod.name.ilike(f'%{term}%'),
            Mod.aliases.ilike(f'%{term}%')
        )
    ).limit(20).all()
    
    resultado = [m.to_dict() for m in mods]
    return jsonify({'resultado': resultado})


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search mods page - accessible to all roles."""
    return render_template('search.html')


@app.route('/analysis', methods=['GET'])
@login_required
@limiter.limit('20 per minute')
def analysis_page():
    """View analysis history - accessible to all roles."""
    # Load history from session if available
    user_key = current_user.username
    history = session.get('logs_history', logs_history.get(user_key, []))
    # Restaurar en memoria para consistencia
    if history:
        logs_history[user_key] = history
        session.permanent = True
    return render_template('analysis.html', resultado=None, logs_history=history)


@app.route('/clear_history', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def clear_history():
    """Clear analysis history for current user."""
    user_key = current_user.username
    # Limpiar de memoria
    if user_key in logs_history:
        del logs_history[user_key]
    # Limpiar de sesión
    session.pop('logs_history', None)
    session.modified = True
    flash('Historial limpiado correctamente', 'success')
    return redirect(url_for('analysis_page'))


@app.route('/analyze', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def analyze():
    """Analyze log - accessible to all roles."""
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('paste_page'))
    log_text = request.form.get('log', '')
    resultado = None
    if not log_text.strip():
        flash('Por favor, pega un log antes de analizar.', 'warning')
        user_key = current_user.username
        history = session.get('logs_history', logs_history.get(user_key, []))
        return render_template('analysis.html', resultado=None, logs_history=history)
    if len(log_text) > MAX_LOG_PASTE_CHARS:
        flash(f'El log es demasiado grande. Máximo {MAX_LOG_PASTE_CHARS} caracteres.', 'danger')
        user_key = current_user.username
        history = session.get('logs_history', logs_history.get(user_key, []))
        return render_template('analysis.html', resultado=None, logs_history=history)

    # Si hay texto, sigue el mismo flujo que /upload
    if log_text.strip():
        resultado = _analyze_log_text_unified(log_text)

        user_key = current_user.username
        if user_key not in logs_history:
            logs_history[user_key] = []
        history_item = {
            'timestamp': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'user': current_user.username,
            'filename': 'pasted_log',
            'resultado': resultado
        }
        logs_history[user_key].insert(0, history_item)
        if len(logs_history[user_key]) > MAX_HISTORY_ITEMS:
            logs_history[user_key].pop()
        session['logs_history'] = logs_history.get(user_key, [])
        session.permanent = True
        session.modified = True
        history_to_display = session.get('logs_history', logs_history.get(current_user.username, []))
        if history_to_display:
            logs_history[current_user.username] = history_to_display
        return render_template('analysis.html', resultado=resultado, logs_history=history_to_display)


@app.route('/paste', methods=['GET'])
@login_required
@limiter.limit('20 per minute')
def paste_page():
    """Paste log page - accessible to all roles."""
    user_key = current_user.username
    history = session.get('logs_history', logs_history.get(user_key, []))
    return render_template('paste.html', logs_history=history, csrf_token=_get_csrf_token())


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit('20 per minute')
def upload():
    """Upload log file - accessible to all roles."""
    if request.method == 'GET':
        user_key = current_user.username
        history = session.get('logs_history', logs_history.get(user_key, []))
        return render_template('upload.html', logs_history=history, csrf_token=_get_csrf_token())

    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('upload'))
    
    f = request.files.get('logfile')
    if not f or f.filename == '':
        flash('No se seleccionó archivo', 'danger')
        return redirect(url_for('upload'))

    filename = secure_filename(f.filename or '')
    ext = Path(filename).suffix.lower()
    if ext not in ('.log', '.txt'):
        flash('Formato no válido. Solo se permiten archivos .log o .txt', 'danger')
        return redirect(url_for('upload'))

    try:
        content = _read_text_filestorage_limited(f, MAX_LOG_UPLOAD_BYTES)
    except ValueError:
        flash(f'Archivo demasiado grande. Máximo {MAX_LOG_UPLOAD_BYTES // (1024 * 1024)}MB.', 'danger')
        return redirect(url_for('upload'))
    
    resultado = _analyze_log_text_unified(content)

    user_key = current_user.username
    if user_key not in logs_history:
        logs_history[user_key] = []
    history_item = {
        'timestamp': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
        'user': current_user.username,
        'filename': filename,
        'resultado': resultado
    }
    logs_history[user_key].insert(0, history_item)
    if len(logs_history[user_key]) > MAX_HISTORY_ITEMS:
        logs_history[user_key].pop()
    session['logs_history'] = logs_history.get(current_user.username, [])
    session.permanent = True
    session.modified = True
    history_to_display = session.get('logs_history', logs_history.get(current_user.username, []))
    if history_to_display:
        logs_history[current_user.username] = history_to_display
    return render_template('analysis.html', resultado=resultado, logs_history=history_to_display)


# ============================================================================
# MOD ROUTES (Require smod or admin role)
# ============================================================================

@app.route('/add_mod', methods=['POST'])
@mod_required
def add_mod():
    """Add new mod - requires smod or admin."""
    nuevo_nombre = request.form.get('name', '').strip()
    
    if not nuevo_nombre:
        flash('El nombre del mod es requerido.', 'danger')
        return redirect(url_for('index'))
    
    # Check for duplicates
    existing = Mod.query.filter_by(name=nuevo_nombre).first()
    if existing:
        flash(f'Ya existe un mod con el nombre "{nuevo_nombre}"', 'danger')
        return redirect(url_for('index'))
    
    # Create new mod
    nuevo = Mod(
        name=nuevo_nombre,
        status=_normalize_status(request.form.get('status', 'prohibido')),
        category=request.form.get('category', '').strip(),
        platform=request.form.get('platform', '').strip(),
        description=request.form.get('description', '').strip(),
        created_by=current_user.id
    )
    
    # Handle aliases
    alias_str = request.form.get('alias', '').strip()
    if alias_str:
        alias_list = [x.strip() for x in alias_str.replace('-', ',').split(',') if x.strip()]
        nuevo.set_aliases_list(alias_list)
    
    db.session.add(nuevo)
    db.session.commit()
    
    # Auto-sync to GitHub
    auto_commit_and_push(f'Add mod: {nuevo_nombre}')
    # Actualizar lista de mods prohibidos automáticamente
    subprocess.run([
        sys.executable, os.path.join(os.path.dirname(__file__), 'get_prohibited_mods.py')
    ])
    
    flash(f'Mod "{nuevo_nombre}" agregado exitosamente.', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:idx>', methods=['GET', 'POST'])
@mod_required
def edit(idx):
    """Edit mod - requires smod or admin."""
    mod = Mod.query.get_or_404(idx)
    
    if request.method == 'POST':
        nuevo_nombre = request.form.get('name', '').strip()
        
        if not nuevo_nombre:
            flash('El nombre del mod es requerido.', 'danger')
            return render_template('edit.html', idx=idx, mod=mod.to_dict())
        
        # Check for duplicates (excluding current mod)
        existing = Mod.query.filter(Mod.name == nuevo_nombre, Mod.id != idx).first()
        if existing:
            flash(f'Ya existe otro mod con el nombre "{nuevo_nombre}"', 'danger')
            return render_template('edit.html', idx=idx, mod=mod.to_dict())
        
        # Update mod
        mod.name = nuevo_nombre
        mod.status = _normalize_status(request.form.get('status', 'prohibido'))
        mod.category = request.form.get('category', '').strip()
        mod.platform = request.form.get('platform', '').strip()
        mod.description = request.form.get('description', '').strip()
        
        # Handle aliases
        alias_str = request.form.get('alias', '').strip()
        if alias_str:
            alias_list = [x.strip() for x in alias_str.replace('-', ',').split(',') if x.strip()]
            mod.set_aliases_list(alias_list)
        else:
            mod.aliases = ''
        
        db.session.commit()
        
        # Auto-sync to GitHub
        auto_commit_and_push(f'Update mod: {nuevo_nombre}')
        # Actualizar lista de mods prohibidos automáticamente
        subprocess.run([
            sys.executable, os.path.join(os.path.dirname(__file__), 'get_prohibited_mods.py')
        ])
        
        flash(f'Mod "{nuevo_nombre}" actualizado exitosamente.', 'success')
        # Limpiar sesión y forzar logout tras update de mod
        session.clear()
        logout_user()
        flash('Por seguridad, vuelve a iniciar sesión tras actualizar un mod.', 'info')
        return redirect(url_for('login'))
    
    return render_template('edit.html', idx=idx, mod=mod.to_dict())


@app.route('/delete/<int:idx>', methods=['POST'])
@mod_required
def delete(idx):
    """Delete mod - requires smod or admin."""
    mod = Mod.query.get_or_404(idx)
    mod_name = mod.name
    
    db.session.delete(mod)
    db.session.commit()
    
    # Auto-sync to GitHub
    auto_commit_and_push(f'Delete mod: {mod_name}')
    # Actualizar lista de mods prohibidos automáticamente
    subprocess.run([
        sys.executable, os.path.join(os.path.dirname(__file__), 'get_prohibited_mods.py')
    ])
    
    flash(f'Mod "{mod_name}" eliminado exitosamente.', 'success')
    return redirect(url_for('index'))


# ============================================================================
# ADMIN ROUTES (Require admin role only)
# ============================================================================

@app.route('/admin/users')
@smod_required
def admin_users():
    """Manage users - smod y admin."""
    ensure_users_last_active_column()
    
    # Definir orden de jerarquía
    role_order = {
        'founder': 0,
        'owner': 1,
        'admin': 2,
        'manager': 3,
        'smod': 4,
        'mod': 5,
        'helper': 6,
        'p-helper': 7,
        'adminpage': 8,
    }
    
    # Obtener todos los usuarios
    all_users = User.query.all()
    
    # Ordenar por jerarquía primero, luego por fecha de creación descendente
    users = sorted(all_users, key=lambda u: (role_order.get(u.role, 999), -u.created_at.timestamp()))
    
    # Marcar online si el usuario fue activo en los últimos ONLINE_TIMEOUT segundos
    now_utc = datetime.utcnow()
    users_with_status = []
    for user in users:
        last_active = getattr(user, 'last_active', None)
        is_online = bool(last_active) and (now_utc - last_active).total_seconds() < ONLINE_TIMEOUT
        users_with_status.append((user, is_online))
    return render_template('admin_users.html', users=users_with_status, csrf_token=_get_csrf_token())


@app.route('/api/heartbeat', methods=['POST'])
@login_required
@limiter.limit('120 per minute')
def api_heartbeat():
    """Client heartbeat to keep online status accurate while idle on a page."""
    ensure_users_last_active_column()
    if not _validate_csrf():
        return jsonify({'ok': False, 'error': 'csrf'}), 400

    try:
        current_user.last_active = datetime.utcnow()
        db.session.commit()
        return jsonify({'ok': True})
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(exc)}), 500


@app.route('/admin/users/<int:user_id>/twofa/reset', methods=['POST'])
@admin_required
@limiter.limit('20 per minute')
def admin_reset_user_twofa(user_id):
    """Admin action: disable and clear 2FA for a user."""
    ensure_users_2fa_columns()
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('admin_users'))

    user = User.query.get_or_404(user_id)
    user.twofa_enabled = False
    user.twofa_secret = None
    user.twofa_confirmed_at = None
    db.session.commit()

    print(f'[2FA] Admin reset 2FA for user: {user.username}', flush=True)
    auto_commit_and_push(f'Reset 2FA for user: {user.username}')
    flash(f'2FA removido para "{user.username}".', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/create', methods=['POST'])
@smod_required
def admin_create_user():
    """Create new user - admin only."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'helper')

    if not all([username, password]):
        flash('Usuario y contraseña son requeridos.', 'danger')
        return redirect(url_for('admin_users'))

    def _placeholder_email_for(username_value: str) -> str:
        base_local = re.sub(r'[^a-z0-9._-]+', '.', (username_value or '').strip().lower()).strip('.')
        if not base_local:
            base_local = 'user'
        candidate = f"{base_local}@change.local"
        if not User.query.filter_by(email=candidate).first():
            return candidate
        # Ensure uniqueness
        for i in range(2, 5000):
            candidate_i = f"{base_local}{i}@change.local"
            if not User.query.filter_by(email=candidate_i).first():
                return candidate_i
        # Fallback (extremely unlikely)
        return f"{base_local}{int(time())}@change.local"

    # If staff doesn't provide an email, generate a unique placeholder.
    if not email:
        email = _placeholder_email_for(username)
    
    # Check if user exists
    if User.query.filter_by(username=username).first():
        flash(f'El usuario "{username}" ya existe.', 'danger')
        return redirect(url_for('admin_users'))
    
    if User.query.filter_by(email=email).first():
        flash(f'El email "{email}" ya está registrado.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Create user
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role=role,
        is_active=True
    )
    
    db.session.add(new_user)
    db.session.commit()
    print(f'[User Management] Creating user: {username}', flush=True)
    auto_commit_and_push(f'Add user: {username}')
    
    flash(f'Usuario "{username}" creado exitosamente.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@smod_required
def admin_toggle_user(user_id):
    """Toggle user active status - admin only."""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('No puedes desactivar tu propia cuenta.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activado' if user.is_active else 'desactivado'
    print(f'[User Management] Toggle user {user.username}: {status}', flush=True)
    auto_commit_and_push(f'Toggle user {user.username}: {status}')
    
    flash(f'Usuario "{user.username}" {status}.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@smod_required
def admin_change_role(user_id):
    """Change user role - smod o admin."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role', 'helper')

    allowed_roles = {
        'founder',
        'owner',
        'admin',
        'manager',
        'smod',
        'mod',
        'helper',
        'p-helper',
        'adminpage',
    }

    if new_role not in allowed_roles:
        flash('Rol inválido.', 'danger')
        return redirect(url_for('admin_users'))

    # AdminPage: solo PonyGamer_uwu puede otorgar ese rango
    if new_role == 'adminpage' and current_user.username != 'PonyGamer_uwu':
        flash('Solo PonyGamer_uwu puede otorgar el rango AdminPage.', 'danger')
        return redirect(url_for('admin_users'))

    # Proteger la cuenta de PonyGamer_uwu: nadie excepto él puede cambiarle el rol
    if user.username == 'PonyGamer_uwu' and current_user.username != 'PonyGamer_uwu':
        flash('El rol de PonyGamer_uwu está bloqueado.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Solo permitir que PonyGamer_uwu cambie su propio rol
    if user.id == current_user.id and current_user.username != 'PonyGamer_uwu':
        flash('No puedes cambiar tu propio rol.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.role = new_role
    db.session.commit()
    print(f'[User Management] Change role {user.username}: {new_role}', flush=True)
    auto_commit_and_push(f'Change role {user.username}: {new_role}')
    
    flash(f'Rol de "{user.username}" cambiado a "{new_role}".', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@smod_required
def admin_edit_user(user_id):
    """Edit user - admin only."""
    user = User.query.get_or_404(user_id)
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not username:
        flash('Usuario es requerido.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Check if username is taken by another user
    existing = User.query.filter(User.username == username, User.id != user_id).first()
    if existing:
        flash(f'El nombre de usuario "{username}" ya está en uso.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Update email only if explicitly provided (email is hidden/removed from UI)
    if email and email != user.email:
        existing = User.query.filter(User.email == email, User.id != user_id).first()
        if existing:
            flash(f'El email "{email}" ya está en uso.', 'danger')
            return redirect(url_for('admin_users'))
    
    # Update user
    user.username = username
    if email:
        user.email = email
    
    # Update password if provided
    if password:
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('admin_users'))
        
        if len(password) < 6:
            flash('La contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('admin_users'))
        
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    db.session.commit()
    print(f'[User Management] Update user: {username}', flush=True)
    auto_commit_and_push(f'Update user: {username}')
    # Limpiar sesión y forzar logout tras update
    session.clear()
    logout_user()
    flash('Por seguridad, vuelve a iniciar sesión tras actualizar el usuario.', 'info')
    return redirect(url_for('login'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@smod_required
def admin_delete_user(user_id):
    """Delete user - admin only."""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.', 'danger')
        return redirect(url_for('admin_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    print(f'[User Management] Delete user: {username}', flush=True)
    auto_commit_and_push(f'Delete user: {username}')
    
    flash(f'Usuario "{username}" eliminado.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/security')
@admin_required
def admin_security():
    """Security dashboard - admin only."""
    blocked_ips = []
    current_time = datetime.now()
    
    ensure_login_attempts_columns()

    # Get from database first (persistent data)
    db_attempts = LoginAttempt.query.all()
    for attempt in db_attempts:
        is_blocked_now = False
        time_remaining_min = 0

        if attempt.blocked_until:
            if current_time < attempt.blocked_until:
                is_blocked_now = True
                time_remaining_min = max(1, int((attempt.blocked_until - current_time).total_seconds() / 60))
            else:
                # Expired lock - clear it (keep history)
                attempt.is_blocked = False
                attempt.blocked_until = None
                attempt.attempts = 0

        # Legacy compatibility: if an old row was marked blocked, interpret as 15m lock from last_attempt.
        if not attempt.blocked_until and (attempt.is_blocked or attempt.attempts >= 5):
            legacy_until = attempt.last_attempt + timedelta(minutes=15)
            if current_time < legacy_until:
                is_blocked_now = True
                time_remaining_min = max(1, int((legacy_until - current_time).total_seconds() / 60))
            else:
                attempt.is_blocked = False
                attempt.attempts = 0

        # Basic cleanup: keep recent items, or anything with block history.
        if not is_blocked_now and int(getattr(attempt, 'block_count', 0) or 0) == 0:
            if (current_time - attempt.last_attempt).total_seconds() > 900:
                db.session.delete(attempt)
                continue

        blocked_ips.append({
            'ip': attempt.ip_address,
            'username': attempt.username if attempt.username else 'desconocido',
            'attempts': attempt.attempts,
            'blocked': is_blocked_now,
            'time_remaining': time_remaining_min,
        })
    db.session.commit()
    
    # Also get from memory for real-time updates
    for ip, data in login_attempts.items():
        try:
            if isinstance(data, tuple):
                if len(data) == 3:
                    attempts, last_attempt, username = data
                elif len(data) == 2:
                    attempts, last_attempt = data
                    username = 'desconocido'
                else:
                    continue
            else:
                continue
        except (ValueError, TypeError):
            continue
        
        time_remaining = 900 - (current_time - last_attempt).total_seconds()
        if time_remaining > 0:
            # Check if already in list from DB
            if not any(item['ip'] == ip for item in blocked_ips):
                blocked_ips.append({
                    'ip': ip,
                    'username': str(username) if username else 'desconocido',
                    'attempts': attempts,
                    'blocked': attempts >= 5,
                    'time_remaining': max(0, int(time_remaining / 60))
                })
    
    # Agrega IPs bloqueadas por el GlobalIPBlocker
    global_blocked = blocker.get_blocked_ips() if blocker else []
    for item in global_blocked:
        if not any(b['ip'] == item['ip'] for b in blocked_ips):
            blocked_ips.append({
                'ip': item['ip'],
                'username': 'Bot/Auto-bloqueado',
                'attempts': item['block_count'],
                'blocked': True,
                'time_remaining': item['time_remaining'],
                'block_count': item['block_count']
            })
    
    # Obtiene alertas recientes del GlobalIPBlocker
    alerts = blocker.get_alerts(limit=20) if blocker else []
    
    return render_template('admin_security.html', blocked_ips=blocked_ips, alerts=alerts)


@app.route('/admin/security/unblock/<ip>', methods=['POST'])
@admin_required
def admin_unblock_ip(ip):
    """Unblock an IP - admin only."""
    # Remove from memory
    if ip in login_attempts:
        del login_attempts[ip]
    
    # Remove from database
    LoginAttempt.query.filter_by(ip_address=ip).delete()
    db.session.commit()
    
    # Remove from GlobalIPBlocker
    if blocker:
        blocker.unblock_ip(ip)
    
    flash(f'IP {ip} desbloqueada exitosamente.', 'success')
    return redirect(url_for('admin_security'))


@app.route('/admin/security/clear-all', methods=['POST'])
@admin_required
def admin_clear_all_blocks():
    """Clear all blocked IPs - admin only."""
    # Count from both memory and database
    count_memory = len(login_attempts)
    count_db = LoginAttempt.query.count()
    
    # Clear both
    login_attempts.clear()
    LoginAttempt.query.delete()
    db.session.commit()
    
    total = count_memory + count_db
    flash(f'{total} direcciones IP desbloqueadas.', 'success')
    return redirect(url_for('admin_security'))


# ===================== CAMBIO DE CONTRASEÑA USUARIO =====================
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not current_user.is_authenticated:
            flash('Debes iniciar sesión.', 'danger')
            return redirect(url_for('login'))
        if not current_password or not new_password or not confirm_password:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('change_password'))
        if not bcrypt.check_password_hash(current_user.password_hash, current_password):
            flash('La contraseña actual es incorrecta.', 'danger')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden.', 'danger')
            return redirect(url_for('change_password'))
        if len(new_password) < 6:
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return redirect(url_for('change_password'))
        current_user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Contraseña cambiada exitosamente.', 'success')
        return redirect(url_for('menu'))
    return render_template('change_password.html')


@app.route('/2fa', methods=['GET'])
@login_required
def twofa_page():
    ensure_users_2fa_columns()
    if not _twofa_role_allowed(current_user):
        _twofa_disable_for_user(current_user)
        session.pop('twofa_setup_secret', None)
        session.modified = True
        flash('2FA solo está disponible para rangos: Founder/Owner/Admin/Manager/Smod.', 'danger')
        return redirect(url_for('menu'))
    # If user is not enabled, create/keep a setup secret in session until verified.
    setup_secret = session.get('twofa_setup_secret')
    if not getattr(current_user, 'twofa_enabled', False):
        if not setup_secret:
            import pyotp
            setup_secret = pyotp.random_base32()
            session['twofa_setup_secret'] = setup_secret
            session.modified = True

        import pyotp
        totp = pyotp.TOTP(setup_secret)
        otpauth_url = totp.provisioning_uri(name=current_user.username, issuer_name=_twofa_issuer_name())
        qr_data_uri = _twofa_qr_data_uri(otpauth_url)
    else:
        otpauth_url = None
        qr_data_uri = None

    return render_template(
        'twofa.html',
        twofa_enabled=bool(getattr(current_user, 'twofa_enabled', False)),
        setup_secret=setup_secret if not getattr(current_user, 'twofa_enabled', False) else None,
        qr_data_uri=qr_data_uri,
        csrf_token=_get_csrf_token(),
    )


@app.route('/2fa/enable', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def twofa_enable():
    ensure_users_2fa_columns()
    if not _twofa_role_allowed(current_user):
        _twofa_disable_for_user(current_user)
        session.pop('twofa_setup_secret', None)
        session.modified = True
        flash('2FA solo está disponible para rangos: Founder/Owner/Admin/Manager/Smod.', 'danger')
        return redirect(url_for('menu'))
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('twofa_page'))

    if getattr(current_user, 'twofa_enabled', False):
        flash('2FA ya está activado en tu cuenta.', 'info')
        return redirect(url_for('twofa_page'))

    code = (request.form.get('code') or '').strip().replace(' ', '')
    secret = session.get('twofa_setup_secret')
    if not secret:
        flash('Sesión de vinculación expirada. Recarga la página.', 'danger')
        return redirect(url_for('twofa_page'))

    import pyotp
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        flash('Código 2FA inválido. Intenta nuevamente.', 'danger')
        return redirect(url_for('twofa_page'))

    current_user.twofa_secret = secret
    current_user.twofa_enabled = True
    current_user.twofa_confirmed_at = datetime.utcnow()
    db.session.commit()

    session.pop('twofa_setup_secret', None)
    session.modified = True
    flash('2FA activado correctamente.', 'success')
    return redirect(url_for('twofa_page'))


@app.route('/2fa/disable', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def twofa_disable():
    ensure_users_2fa_columns()
    if not _twofa_role_allowed(current_user):
        _twofa_disable_for_user(current_user)
        session.pop('twofa_setup_secret', None)
        session.modified = True
        flash('2FA solo está disponible para rangos: Founder/Owner/Admin/Manager/Smod.', 'danger')
        return redirect(url_for('menu'))
    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('twofa_page'))

    if not getattr(current_user, 'twofa_enabled', False):
        flash('2FA no está activado.', 'info')
        return redirect(url_for('twofa_page'))

    password = request.form.get('password', '')
    code = (request.form.get('code') or '').strip().replace(' ', '')
    if not bcrypt.check_password_hash(current_user.password_hash, password):
        flash('Contraseña incorrecta.', 'danger')
        return redirect(url_for('twofa_page'))

    import pyotp
    totp = pyotp.TOTP(current_user.twofa_secret or '')
    if not totp.verify(code, valid_window=1):
        flash('Código 2FA inválido.', 'danger')
        return redirect(url_for('twofa_page'))

    current_user.twofa_enabled = False
    current_user.twofa_secret = None
    current_user.twofa_confirmed_at = None
    db.session.commit()
    flash('2FA desactivado.', 'success')
    return redirect(url_for('twofa_page'))


@app.route('/2fa/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def twofa_login_verify():
    """Second step of login for users with 2FA enabled."""
    ensure_users_2fa_columns()
    pending_user_id = session.get('twofa_pending_user_id')
    if not pending_user_id:
        return redirect(url_for('login'))

    user = db.session.get(User, int(pending_user_id))
    if not user:
        session.pop('twofa_pending_user_id', None)
        return redirect(url_for('login'))

    # Safety: if role is not allowed, don't keep user stuck in 2FA flow.
    if not _twofa_role_allowed(user):
        _twofa_disable_for_user(user)
        session.pop('twofa_pending_user_id', None)
        session.modified = True
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('twofa_login.html', csrf_token=_get_csrf_token(), username=user.username)

    if not _validate_csrf():
        flash('Solicitud inválida. Recarga la página e intenta nuevamente.', 'danger')
        return redirect(url_for('twofa_login_verify'))

    code = (request.form.get('code') or '').strip().replace(' ', '')
    import pyotp
    totp = pyotp.TOTP(user.twofa_secret or '')
    if not totp.verify(code, valid_window=1):
        flash('Código 2FA inválido.', 'danger')
        return redirect(url_for('twofa_login_verify'))

    session.pop('twofa_pending_user_id', None)
    session.modified = True
    login_user(user, remember=True)
    flash(f'¡Bienvenido, {user.username}!', 'success')
    return redirect(url_for('menu'))


# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Content Security Policy (adjust as needed)
    if os.environ.get('FLASK_ENV') == 'production':
        # CSP: allow required CDNs for Bootstrap/JS + Google Fonts used by templates.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "connect-src 'self' https://cdn.jsdelivr.net"
        )
    return response


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors."""
    # If it's an AJAX request or expects JSON, return JSON error
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return {'error': 'No tienes permisos suficientes'}, 403
    
    # Otherwise flash message and redirect to menu
    flash('No tienes permisos suficientes. Se requiere rol: mod, smod o admin', 'danger')
    return redirect(url_for('menu'))


@app.errorhandler(404)
def not_found(e):
    """Handle 404 Not Found errors."""
    requested_path = request.path
    error_msg = f'La página "{requested_path}" no se ha encontrado.'
    return render_template('error.html', error_code=404, error_message=error_msg), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 Internal Server errors."""
    db.session.rollback()
    return render_template('error.html', error_code=500, error_message='Error interno del servidor.'), 500


@app.errorhandler(413)
def request_entity_too_large(e):
    """Handle file too large errors."""
    flash('El archivo es demasiado grande. Máximo 16MB.', 'danger')
    return redirect(url_for('upload'))


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        # Runtime migrations
        ensure_login_attempts_columns()
        ensure_users_2fa_columns()
    
    # Run app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
