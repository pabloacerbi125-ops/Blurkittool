# Editar nombre de modalidad
"""Flask web application for BlurkitModsTool with authentication.

Multi-user system with role-based permissions and SQLite database.
"""

import sys
import os
import subprocess
import re
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_limiter import Limiter
from markupsafe import Markup, escape
from sqlalchemy import inspect, text
from werkzeug.utils import secure_filename

# Función para obtener la IP real incluso detrás de proxy (Render)
def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

from time import time

# Tiempo máximo para considerar a un usuario como online (en segundos)
ONLINE_TIMEOUT = 180  # 3 minutos

# Diccionario en memoria para usuarios online
online_users = {}

# ============================================================================
# AUTO GIT PULL ON STARTUP (keep database in sync)
# ============================================================================

def auto_git_pull_on_startup():
    """Pull latest changes from GitHub on app startup.
    
    Ensures database is always in sync between local and Render.
    Runs silently - doesn't interrupt app if git is unavailable.
    Only runs in production (Render), not in local development.
    """
    try:
        # Skip auto-pull in local development
        if os.environ.get('FLASK_ENV') != 'production':
            return
        
        repo_path = Path(__file__).resolve().parent.parent
        
        # Only pull if .git folder exists
        if not (repo_path / '.git').exists():
            return
        
        # Configure git
        subprocess.run(
            ['git', 'config', 'user.email', 'auto-sync@blurkittool.local'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        subprocess.run(
            ['git', 'config', 'user.name', 'Auto Sync'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        
        # Fetch and reset to origin/main (works in detached HEAD state on Render)
        subprocess.run(
            ['git', 'fetch', 'origin', 'main', '--quiet'],
            cwd=repo_path,
            capture_output=True,
            timeout=10
        )
        result = subprocess.run(
            ['git', 'reset', '--hard', 'origin/main'],
            cwd=repo_path,
            capture_output=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("[Auto-sync] Database synced from GitHub", flush=True)
        else:
            print(f"[Auto-sync warning] Git pull failed: {result.stderr.decode()}", flush=True)
    except Exception as e:
        # Silently fail - don't interrupt app startup
        print(f"[Auto-sync error] {str(e)}", flush=True)

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

# Flask app with proper paths
app = Flask(__name__)


_modalidad_orden_ready = False
_regla_orden_ready = False
_login_attempts_ready = False


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

    escaped = escape(str(text))

    def repl(match):
        return f'<span class="prohibido-word">{match.group(0)}</span>'

    highlighted = re.sub(r'\bPROHIBIDO\b', repl, str(escaped), flags=re.IGNORECASE)
    return Markup(highlighted)

@app.route('/editar_modalidad/<int:modalidad_id>', methods=['POST'])
@login_required
@admin_required
def editar_modalidad(modalidad_id):
    modalidad = Modalidad.query.get_or_404(modalidad_id)
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
def editar_regla(regla_id):
    regla = Regla.query.get_or_404(regla_id)
    ensure_regla_orden_column()
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
limiter = Limiter(get_real_ip, app=app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

@app.route('/menu')
@login_required
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
def api_analyze_log():
    """API endpoint para analizar logs de Minecraft. Recibe texto plano o archivo."""
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        f = request.files.get('logfile')
        if not f or f.filename == '':
            return jsonify({'error': 'No se seleccionó archivo'}), 400
        try:
            content = f.read().decode('utf-8', errors='ignore')
        except Exception:
            content = f.read().decode('latin-1', errors='ignore')
        log_lines = content.splitlines()
    else:
        log_text = request.get_data(as_text=True)
        if not log_text.strip():
            return jsonify({'error': 'No se envió contenido'}), 400
        log_lines = log_text.splitlines()
    result = analyze_log_lines(log_lines)
    return jsonify(result)
from models import LoginAttempt
app.config['PERMANENT_SESSION_LIFETIME'] = 600  # 10 minutos
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database path - use absolute path
basedir = Path(__file__).resolve().parent
db_path = basedir / 'instance' / 'blurkit.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True


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

# Auto-pull database changes on app startup
auto_git_pull_on_startup()


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except:
        return None


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


# ============================================================================
# PUBLIC ROUTES (No login required)
# ============================================================================

# Rate limiting - simple in-memory storage (use Redis in production)
login_attempts = {}

# In-memory history cache for session support (primary storage is in Flask sessions)
# Structure: {username: [{'timestamp': str, 'filename': str, 'resultado': dict}, ...]}
logs_history = {}
MAX_HISTORY_ITEMS = 20

# ============================================================================
# GIT AUTO-SYNC FUNCTION (for Render deployment)
# ============================================================================

def auto_commit_and_push(message):
    """Auto-commit database changes and push to GitHub.
    
    Uses GITHUB_TOKEN environment variable for authentication.
    Only works on Render or environments with git configured.
    """
    try:
        # Only run in production (Render) to avoid local pushes
        if os.environ.get('FLASK_ENV') != 'production':
            print("[Auto-sync] Skipped: Not running in production", flush=True)
            return False

        # Only run if token is configured (production/Render)
        github_token = os.environ.get('GITHUB_TOKEN')
        if not github_token:
            print(f"[Auto-sync] Skipped: No GITHUB_TOKEN configured", flush=True)
            return False
        
        print(f"[Auto-sync] Starting push: {message}", flush=True)
        
        repo_path = Path(__file__).resolve().parent.parent
        
        # Configure git with token (temporary, for this session)
        subprocess.run(
            ['git', 'config', 'user.email', 'render-auto-sync@blurkittool.local'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        subprocess.run(
            ['git', 'config', 'user.name', 'Render Auto-Sync'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        
        # Pull antes de hacer commit/push
        subprocess.run(
            ['git', 'pull', 'origin', 'main', '--rebase'],
            cwd=repo_path,
            capture_output=True,
            timeout=10
        )

        # Stage database file
        subprocess.run(
            ['git', 'add', 'web/instance/blurkit.db'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        
        # Check if there are changes
        result = subprocess.run(
            ['git', 'diff', '--cached', '--quiet'],
            cwd=repo_path,
            capture_output=True,
            timeout=5
        )
        
        if result.returncode != 0:  # There are changes
            # Commit
            commit_result = subprocess.run(
                ['git', 'commit', '-m', message],
                cwd=repo_path,
                capture_output=True,
                timeout=5
            )
            print(f"[Auto-sync] Commit result: {commit_result.returncode}", flush=True)
            
            # Push with token
            # Format: https://<token>@github.com/<user>/<repo>.git
            remote_url = f'https://{github_token}@github.com/pabloacerbi125-ops/Blurkittool.git'
            push_result = subprocess.run(
                ['git', 'push', remote_url, 'HEAD:main'],  # use HEAD because Render runs in detached HEAD
                cwd=repo_path,
                capture_output=True,
                timeout=10
            )
            print(f"[Auto-sync] Push result: {push_result.returncode}", flush=True)
            if push_result.returncode == 0:
                print(f"[Auto-sync] SUCCESS: {message}", flush=True)
            else:
                print(f"[Auto-sync] Push failed: {push_result.stderr.decode()}", flush=True)
            return push_result.returncode == 0
        else:
            print(f"[Auto-sync] No changes to commit", flush=True)
            return False
    except Exception as e:
        # Silently fail - don't interrupt the app
        print(f"[Auto-sync error] {str(e)}", flush=True)
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with rate limiting."""
    if current_user.is_authenticated:
        return redirect(url_for('menu'))
    
    if request.method == 'POST':
        ensure_login_attempts_columns()

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

            # Update last login
            user.last_login = datetime.now()
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
    search = request.args.get('search', '').strip().lower()
    all_mods = Mod.query.order_by(Mod.name).all()
    filtered_mods = []
    for m in all_mods:
        m_dict = m.to_dict()
        name = m_dict['name'].lower() if m_dict['name'] else ''
        aliases = ','.join(m_dict.get('alias', [])).lower() if m_dict.get('alias') else ''
        if not search or search in name or search in aliases:
            filtered_mods.append(m_dict)
    permitidos = [(idx, m) for idx, m in enumerate(filtered_mods) if m['status'] == 'permitido']
    prohibidos = [(idx, m) for idx, m in enumerate(filtered_mods) if m['status'] == 'prohibido']
    return render_template('modsjg.html', permitidos=permitidos, prohibidos=prohibidos)


@app.route('/reglas')
def reglas():
    """Public rules page - separate page for viewing rules."""
    ensure_modalidad_orden_column()
    ensure_regla_orden_column()
    modalidades = Modalidad.query.order_by(Modalidad.orden.asc(), Modalidad.nombre.asc()).all()
    return render_template('reglas.html', modalidades=modalidades)


@app.route('/reglasadm', methods=['GET', 'POST'])
def reglasadm():
    """Admin rules management - view and create modalities, and show/add rules for selected modality."""
    ensure_modalidad_orden_column()
    ensure_regla_orden_column()
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
def reordenar_modalidades():
    """Persist drag-and-drop ordering for modalidades."""
    ensure_modalidad_orden_column()

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
def editar_nota_modalidad(modalidad_id):
    modalidad = Modalidad.query.get_or_404(modalidad_id)
    nueva_nota = request.form.get('nueva_nota', '').strip()
    modalidad.nota = nueva_nota
    db.session.commit()
    flash('Nota de la modalidad actualizada.', 'success')
    return redirect(url_for('reglasadm', modalidad_id=modalidad_id))

@app.route('/eliminar_modalidad/<int:modalidad_id>', methods=['POST'])
def eliminar_modalidad(modalidad_id):
    modalidad = Modalidad.query.get_or_404(modalidad_id)
    db.session.delete(modalidad)
    db.session.commit()
    flash('Modalidad eliminada correctamente.', 'success')
    return redirect(url_for('reglasadm'))


@app.route('/eliminar_regla/<int:regla_id>', methods=['POST'])
def eliminar_regla(regla_id):
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


@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    """Search mods - accessible to all roles."""
    resultado = None
    if request.method == 'POST':
        term = request.form.get('term', '').lower().strip()
        
        # Search in name and aliases
        mods = Mod.query.filter(
            db.or_(
                Mod.name.ilike(f'%{term}%'),
                Mod.aliases.ilike(f'%{term}%')
            )
        ).all()
        
        resultado = [m.to_dict() for m in mods]
    
    return render_template('search.html', resultado=resultado)


@app.route('/analysis', methods=['GET'])
@login_required
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
def analyze():
    """Analyze log - accessible to all roles."""
    log_text = request.form.get('log', '')
    resultado = None
    if not log_text.strip():
        flash('Por favor, pega un log antes de analizar.', 'warning')
        user_key = current_user.username
        history = session.get('logs_history', logs_history.get(user_key, []))
        return render_template('analysis.html', resultado=None, logs_history=history)
    # Si hay texto, sigue el flujo normal
    if log_text.strip():
        from core import analyze_log_with_gpt
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        if openai_api_key:
            resultado = analyze_log_with_gpt(log_text, openai_api_key)
            # Si hay error, fallback al análisis local
            if resultado.get('error'):
                from analyze_mc_log_utils import analyze_log_lines
                resultado = analyze_log_lines(log_text.splitlines())
        else:
            from analyze_mc_log_utils import analyze_log_lines
            resultado = analyze_log_lines(log_text.splitlines())

        # Si la IA no detectó el nombre del jugador, intenta extraerlo localmente
        if not resultado.get('player'):
            from analyze_mc_log_utils import extract_player
            resultado['player'] = extract_player(log_text.splitlines())

        # Clasificar mods y dependencias igual que en upload
        mods = resultado.get('mods', [])
        dependencies = resultado.get('dependencies', [])
        mods_prohibidos = []
        mods_permitidos = []
        mods_desconocidos = []
        # Mejor comparación: ignora mayúsculas/minúsculas y espacios, busca en aliases
        all_mods_db = list(Mod.query.all())
        def match_mod(mod_name):
            mod_name_norm = mod_name.lower().replace(' ', '')
            for m in all_mods_db:
                # Normaliza nombre y aliases
                db_name = m.name.lower().replace(' ', '')
                if mod_name_norm == db_name:
                    return m
                if m.aliases:
                    for alias in m.aliases.split(','):
                        if mod_name_norm == alias.strip().lower().replace(' ', ''):
                            return m
            return None

        for mod in mods:
            mod_name = mod['name']
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
        # Clasificar dependencias/librerías igual que mods
        dependencias_permitidas = []
        dependencias_prohibidas = []
        dependencias_desconocidas = []
        for dep in dependencies:
            dep_name = dep['name'].lower()
            db_mod = mods_db.get(dep_name)
            if db_mod:
                if db_mod.status == 'prohibido':
                    dependencias_prohibidas.append({**dep, 'category': db_mod.category, 'platform': db_mod.platform})
                elif db_mod.status == 'permitido':
                    dependencias_permitidas.append({**dep, 'category': db_mod.category, 'platform': db_mod.platform})
                else:
                    dependencias_desconocidas.append(dep)
            else:
                dependencias_desconocidas.append(dep)

        resultado['mods_prohibidos'] = mods_prohibidos
        resultado['mods_permitidos'] = mods_permitidos
        resultado['mods_desconocidos'] = mods_desconocidos
        resultado['dependencias_permitidas'] = dependencias_permitidas
        resultado['dependencias_prohibidas'] = dependencias_prohibidas
        resultado['dependencias_desconocidas'] = dependencias_desconocidas
        resultado['dependencias'] = dependencies  # Para compatibilidad con el frontend
        resultado['total'] = len(mods) + len(dependencies)
        resultado['total_mods'] = len(mods_permitidos) + len(mods_prohibidos) + len(mods_desconocidos)

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
def paste_page():
    """Paste log page - accessible to all roles."""
    user_key = current_user.username
    history = session.get('logs_history', logs_history.get(user_key, []))
    if request.method == 'POST':
        log_text = request.form.get('logtext', '')
        from core import analyze_log_with_gpt
        openai_api_key = os.environ.get('OPENAI_API_KEY')
        if openai_api_key:
            resultado = analyze_log_with_gpt(log_text, openai_api_key)
            if resultado.get('error'):
                from analyze_mc_log_utils import analyze_log_lines
                resultado = analyze_log_lines(log_text.splitlines())
        else:
            from analyze_mc_log_utils import analyze_log_lines
            resultado = analyze_log_lines(log_text.splitlines())

        # Guardar en historial igual que upload
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
    return render_template('paste.html', logs_history=history)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload log file - accessible to all roles."""
    if request.method == 'GET':
        user_key = current_user.username
        history = session.get('logs_history', logs_history.get(user_key, []))
        return render_template('upload.html', logs_history=history)
    
    f = request.files.get('logfile')
    if not f or f.filename == '':
        flash('No se seleccionó archivo', 'danger')
        return render_template('upload.html')
    
    filename = f.filename
    try:
        content = f.read().decode('utf-8', errors='ignore')
    except Exception:
        content = f.read().decode('latin-1', errors='ignore')
    
    # Usar GPT-3.5-turbo si la variable de entorno está presente
    from core import analyze_log_with_gpt
    openai_api_key = os.environ.get('OPENAI_API_KEY')
    if openai_api_key:
        resultado = analyze_log_with_gpt(content, openai_api_key)
        # Si hay error, fallback al análisis local
        if resultado.get('error'):
            resultado = analyze_log_lines(content.splitlines())
    else:
        resultado = analyze_log_lines(content.splitlines())

    # Adaptar el resultado IA (allowed/unknown/mods_main/dependencies) a los campos esperados por el frontend
    # Log de depuración: guardar el JSON crudo de la IA para inspección
    import logging
    logging.basicConfig(level=logging.INFO)
    with open('ia_raw_result.json', 'w', encoding='utf-8') as f:
        import json as _json
        f.write(_json.dumps(resultado, ensure_ascii=False, indent=2))
    # Si la IA ya devuelve la estructura final, solo la copiamos y calculamos el total
    if all(k in resultado for k in ['mods_permitidos', 'mods_prohibidos', 'mods_desconocidos', 'dependencias']):
        resultado['total'] = (
            len(resultado['mods_permitidos'])
            + len(resultado['mods_prohibidos'])
            + len(resultado['mods_desconocidos'])
            + len(resultado['dependencias'])
        )
        resultado['total_mods'] = (
            len(resultado['mods_permitidos'])
            + len(resultado['mods_prohibidos'])
            + len(resultado['mods_desconocidos'])
        )
    elif any(k in resultado for k in ['allowed', 'unknown', 'mods_main', 'dependencies']):
        pass  # Aquí iría el código legacy si se necesitara
    # Si la IA no detectó el nombre del jugador, intenta extraerlo localmente
    if not resultado.get('player'):
        from analyze_mc_log_utils import extract_player
        resultado['player'] = extract_player(content.splitlines())

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
        status=request.form.get('status', 'prohibido'),
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
        mod.status = request.form.get('status', 'prohibido')
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
    users = User.query.order_by(User.created_at.desc()).all()
    # Marcar online si el usuario está en online_users y fue activo en los últimos 3 minutos
    now = time()
    users_with_status = []
    for user in users:
        last_seen = online_users.get(user.username)
        is_online = last_seen is not None and (now - last_seen) < ONLINE_TIMEOUT
        users_with_status.append((user, is_online))
    return render_template('admin_users.html', users=users_with_status)


@app.route('/admin/users/create', methods=['POST'])
@admin_required
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
@admin_required
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
@admin_required
def admin_change_role(user_id):
    """Change user role - admin only."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role', 'helper')
    
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
@admin_required
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
@admin_required
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
    
    return render_template('admin_security.html', blocked_ips=blocked_ips)


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
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net"
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
    
    # Run app
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
