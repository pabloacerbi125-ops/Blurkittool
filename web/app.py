"""Flask web application for BlurkitModsTool with authentication.

Multi-user system with role-based permissions and SQLite database.
"""

import sys
import os
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime

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
from core import analizar_log_desde_lineas

# Flask app with proper paths
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
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


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except:
        return None


# ============================================================================
# PUBLIC ROUTES (No login required)
# ============================================================================

# Rate limiting - simple in-memory storage (use Redis in production)
login_attempts = {}

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
            attempts, last_attempt = login_attempts[ip_address]
            # Reset after 15 minutes
            if (current_time - last_attempt).total_seconds() > 900:
                login_attempts[ip_address] = (1, current_time)
            elif attempts >= 5:
                flash('Demasiados intentos fallidos. Intenta de nuevo en 15 minutos.', 'danger')
                return render_template('login.html')
            else:
                login_attempts[ip_address] = (attempts + 1, current_time)
        else:
            login_attempts[ip_address] = (1, current_time)
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Tu cuenta está desactivada. Contacta al administrador.', 'danger')
                return redirect(url_for('login'))
            
            # Reset login attempts on success
            if ip_address in login_attempts:
                del login_attempts[ip_address]
            
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
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Logout current user."""
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('login'))


# ============================================================================
# AUTHENTICATED ROUTES (Login required, all roles can access)
# ============================================================================

@app.route('/')
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
    mods = Mod.query.order_by(Mod.name).all()
    prohibidos = [(m.id, m) for m in mods if m.status == 'prohibido']
    permitidos = [(m.id, m) for m in mods if m.status == 'permitido']
    return render_template('index.html', prohibidos=prohibidos, permitidos=permitidos)


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


@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """Analyze log - accessible to all roles."""
    log_text = request.form.get('log', '')
    resultado = ''
    
    if log_text.strip():
        # Get all mods as dict for analysis
        mods = Mod.query.all()
        mods_data = [m.to_dict() for m in mods]
        resultado = analizar_log_desde_lineas(log_text.splitlines(), mods_data)
    
    return render_template('analysis.html', resultado=resultado)


@app.route('/paste', methods=['GET'])
@login_required
def paste_page():
    """Paste log page - accessible to all roles."""
    return render_template('paste.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload log file - accessible to all roles."""
    if request.method == 'GET':
        return render_template('upload.html')
    
    f = request.files.get('logfile')
    if not f:
        return render_template('analysis.html', resultado='No se subió archivo.')
    
    try:
        content = f.read().decode('utf-8', errors='ignore')
    except Exception:
        content = f.read().decode('latin-1', errors='ignore')
    
    mods = Mod.query.all()
    mods_data = [m.to_dict() for m in mods]
    resultado = analizar_log_desde_lineas(content.splitlines(), mods_data)
    
    return render_template('analysis.html', resultado=resultado)


# ============================================================================
# MOD ROUTES (Require mod, smod or admin role)
# ============================================================================

@app.route('/add_mod', methods=['POST'])
@mod_required
def add_mod():
    """Add new mod - requires mod, smod or admin."""
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
    
    flash(f'Mod "{nuevo_nombre}" agregado exitosamente.', 'success')
    return redirect(url_for('index'))


@app.route('/edit/<int:idx>', methods=['GET', 'POST'])
@mod_required
def edit(idx):
    """Edit mod - requires mod, smod or admin."""
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
        
        flash(f'Mod "{nuevo_nombre}" actualizado exitosamente.', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', idx=idx, mod=mod.to_dict())


@app.route('/delete/<int:idx>', methods=['POST'])
@mod_required
def delete(idx):
    """Delete mod - requires mod, smod or admin."""
    mod = Mod.query.get_or_404(idx)
    mod_name = mod.name
    
    db.session.delete(mod)
    db.session.commit()
    
    flash(f'Mod "{mod_name}" eliminado exitosamente.', 'success')
    return redirect(url_for('index'))


# ============================================================================
# ADMIN ROUTES (Require admin role only)
# ============================================================================

@app.route('/admin/users')
@admin_required
def admin_users():
    """Manage users - admin only."""
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
    
    flash(f'Usuario "{username}" eliminado.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/security')
@admin_required
def admin_security():
    """Security dashboard - admin only."""
    # Get blocked IPs with attempt info
    blocked_ips = []
    current_time = datetime.now()
    
    for ip, (attempts, last_attempt) in login_attempts.items():
        time_remaining = 900 - (current_time - last_attempt).total_seconds()
        if time_remaining > 0:
            blocked_ips.append({
                'ip': ip,
                'attempts': attempts,
                'blocked': attempts >= 5,
                'time_remaining': max(0, int(time_remaining / 60))  # minutes
            })
    
    return render_template('admin_security.html', blocked_ips=blocked_ips)


@app.route('/admin/security/unblock/<ip>', methods=['POST'])
@admin_required
def admin_unblock_ip(ip):
    """Unblock an IP - admin only."""
    if ip in login_attempts:
        del login_attempts[ip]
        flash(f'IP {ip} desbloqueada exitosamente.', 'success')
    else:
        flash(f'IP {ip} no está bloqueada.', 'info')
    
    return redirect(url_for('admin_security'))


@app.route('/admin/security/clear-all', methods=['POST'])
@admin_required
def admin_clear_all_blocks():
    """Clear all blocked IPs - admin only."""
    count = len(login_attempts)
    login_attempts.clear()
    flash(f'{count} direcciones IP desbloqueadas.', 'success')
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
