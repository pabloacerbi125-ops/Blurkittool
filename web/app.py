"""Flask web application for BlurkitModsTool with authentication.

Multi-user system with role-based permissions and SQLite database.
"""

import sys
import os
import subprocess
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime

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

from models import db, User, Mod
from auth import login_required, roles_required, mod_required, smod_required, admin_required
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_mc_log_utils import analyze_log_lines
# ===================== API: Análisis de logs Minecraft =====================
from flask import jsonify

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

# Flask app with proper paths
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 600  # 10 minutos
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database path - use absolute path
basedir = Path(__file__).resolve().parent
db_path = basedir / 'instance' / 'blurkit.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        
        # Simple rate limiting (5 attempts per IP)
        current_time = datetime.now()
        if ip_address in login_attempts:
            attempts, last_attempt, last_username = login_attempts[ip_address]
            # Reset after 15 minutes
            if (current_time - last_attempt).total_seconds() > 900:
                login_attempts[ip_address] = (1, current_time, username)
            elif attempts >= 5:
                flash('Demasiados intentos fallidos. Intenta de nuevo en 15 minutos.', 'danger')
                return render_template('login.html')
            else:
                login_attempts[ip_address] = (attempts + 1, current_time, username)
        else:
            login_attempts[ip_address] = (1, current_time, username)
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Tu cuenta está desactivada. Contacta al administrador.', 'danger')
                return redirect(url_for('login'))
            
            # Reset login attempts on success
            if ip_address in login_attempts:
                del login_attempts[ip_address]
            
            # Clear from database on successful login
            LoginAttempt.query.filter_by(ip_address=ip_address).delete()
            db.session.commit()
            
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
            # Save failed attempt to database
            attempt = LoginAttempt.query.filter_by(ip_address=ip_address).first()
            if attempt:
                attempt.attempts += 1
                attempt.last_attempt = current_time
                attempt.username = username
                attempt.is_blocked = attempt.attempts >= 5
            else:
                attempt = LoginAttempt(
                    ip_address=ip_address,
                    username=username,
                    attempts=1,
                    last_attempt=current_time,
                    is_blocked=False
                )
                db.session.add(attempt)
            db.session.commit()
            
            flash('Usuario o contraseña incorrectos.', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
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
    """Public mods list page - separate page for viewing mods."""
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
    return render_template('reglas.html')


# ============================================================================
# AUTHENTICATED ROUTES (Login required, all roles can access)
# ============================================================================

@app.route('/dashboard')
@login_required
def menu():
    """Visual menu with cards - accessible to all logged-in users."""
    total_mods = Mod.query.count()
    prohibidos_count = Mod.query.filter_by(status='prohibido').count()
    permitidos_count = Mod.query.filter_by(status='permitido').count()
    
    stats = {
        'total': total_mods,
        'prohibidos': prohibidos_count,
        'permitidos': permitidos_count
    }
    
    return render_template('menu.html', stats=stats)


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
    
    if log_text.strip():
        resultado = analyze_log_lines(log_text.splitlines())
        # Categorize mods for template/JS compatibility
        mods = resultado.get('mods', [])
        mods_prohibidos = []
        mods_permitidos = []
        mods_desconocidos = []
        for mod in mods:
            # Use Mod model to check status
            db_mod = Mod.query.filter_by(name=mod['name']).first()
            if db_mod:
                if db_mod.status == 'prohibido':
                    mods_prohibidos.append({**mod, 'category': db_mod.category, 'platform': db_mod.platform})
                elif db_mod.status == 'permitido':
                    mods_permitidos.append({**mod, 'category': db_mod.category, 'platform': db_mod.platform})
                else:
                    mods_desconocidos.append(mod)
            else:
                mods_desconocidos.append(mod)
        resultado['mods_prohibidos'] = mods_prohibidos
        resultado['mods_permitidos'] = mods_permitidos
        resultado['mods_desconocidos'] = mods_desconocidos
        resultado['total'] = len(mods)

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
        session['logs_history'] = logs_history.get(current_user.username, [])
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
    
    resultado = analyze_log_lines(content.splitlines())
    # Categorize mods for template/JS compatibility
    mods = resultado.get('mods', [])
    mods_prohibidos = []
    mods_permitidos = []
    mods_desconocidos = []
    for mod in mods:
        db_mod = Mod.query.filter_by(name=mod['name']).first()
        if db_mod:
            if db_mod.status == 'prohibido':
                mods_prohibidos.append({**mod, 'category': db_mod.category, 'platform': db_mod.platform})
            elif db_mod.status == 'permitido':
                mods_permitidos.append({**mod, 'category': db_mod.category, 'platform': db_mod.platform})
            else:
                mods_desconocidos.append(mod)
        else:
            mods_desconocidos.append(mod)
    resultado['mods_prohibidos'] = mods_prohibidos
    resultado['mods_permitidos'] = mods_permitidos
    resultado['mods_desconocidos'] = mods_desconocidos
    resultado['total'] = len(mods)

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
        
        flash(f'Mod "{nuevo_nombre}" actualizado exitosamente.', 'success')
        return redirect(url_for('index'))
    
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
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_create_user():
    """Create new user - admin only."""
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'helper')
    
    if not all([username, email, password]):
        flash('Todos los campos son requeridos.', 'danger')
        return redirect(url_for('admin_users'))
    
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
    
    if user.id == current_user.id:
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
    
    if not username or not email:
        flash('Usuario y email son requeridos.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Check if username is taken by another user
    existing = User.query.filter(User.username == username, User.id != user_id).first()
    if existing:
        flash(f'El nombre de usuario "{username}" ya está en uso.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Check if email is taken by another user
    existing = User.query.filter(User.email == email, User.id != user_id).first()
    if existing:
        flash(f'El email "{email}" ya está en uso.', 'danger')
        return redirect(url_for('admin_users'))
    
    # Update user
    user.username = username
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
    
    flash(f'Usuario "{username}" actualizado exitosamente.', 'success')
    return redirect(url_for('admin_users'))


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
    
    # Get from database first (persistent data)
    db_attempts = LoginAttempt.query.all()
    for attempt in db_attempts:
        # Skip if older than 15 minutes
        if (current_time - attempt.last_attempt).total_seconds() > 900:
            db.session.delete(attempt)
            continue
            
        blocked_ips.append({
            'ip': attempt.ip_address,
            'username': attempt.username if attempt.username else 'desconocido',
            'attempts': attempt.attempts,
            'blocked': attempt.is_blocked or attempt.attempts >= 5,
            'time_remaining': max(0, int((900 - (current_time - attempt.last_attempt).total_seconds()) / 60))
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
