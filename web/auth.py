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
    """Decorator to require mod, smod or admin role."""
    return roles_required('mod', 'smod', 'admin')(f)


def smod_required(f):
    """Decorator to require smod or admin role."""
    return roles_required('smod', 'admin')(f)


def admin_required(f):
    """Decorator to require admin role."""
    return roles_required('admin')(f)
