"""Authentication decorators and utilities for BlurkitModsTool.

Provides role-based access control decorators.
"""

from functools import wraps
from flask import flash, redirect, url_for, abort
from flask_login import current_user


def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Por favor inicia sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*roles):
    """Decorator to require specific roles for a route.
    
    Usage:
        @roles_required('admin')
        @roles_required('mod', 'smod', 'admin')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Por favor inicia sesión para acceder a esta página.', 'warning')
                return redirect(url_for('login'))
            
            if not current_user.has_role(*roles):
                # Don't execute the function - abort immediately
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def mod_required(f):
    """Decorator to require smod, admin o adminpage (mod no longer edits)."""
    return roles_required('smod', 'admin', 'adminpage')(f)


def smod_required(f):
    """Decorator to require smod, admin o adminpage."""
    return roles_required('smod', 'admin', 'adminpage')(f)


def admin_required(f):
    """Decorator to require admin o adminpage."""
    return roles_required('admin', 'adminpage')(f)


def ss_session_required(f):
    """Decorator to require valid SS session (Herramientas SS con 2FA temporal).
    
    Valida que el token no haya expirado (10 minutos máximo).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import session
        from models import SSSession
        
        ss_token = session.get('ss_token')

        if not ss_token:
            flash('Debes iniciar sesión con Herramientas SS para acceder.', 'warning')
            return redirect(url_for('login'))

        ss_sess = SSSession.query.filter_by(token=ss_token).first()
        if not ss_sess or not ss_sess.is_valid():
            session.pop('ss_token', None)
            session.pop('ss_user_id', None)
            flash('Sesión SS expirada. Inicia de nuevo con tu código 2FA.', 'warning')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function
