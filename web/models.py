"""Modelos de base de datos para BlurkitModsTool.

Define los modelos `User` y `Mod` con SQLAlchemy.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Modelo de usuario con permisos basados en roles."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    _role = db.Column('role', db.String(20), nullable=False, default='helper')  # helper, mod, smod, admin, adminpage

    @property
    def role(self):
        return self._role

    @role.setter
    def role(self, value):
        self._role = value
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    last_active = db.Column(db.DateTime)

    # 2FA (TOTP, compatible con Google Authenticator)
    twofa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    twofa_secret = db.Column(db.String(64), nullable=True)
    twofa_confirmed_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'
    
    def has_role(self, *roles):
        """Verifica si el usuario tiene alguno de los roles especificados.

        Reglas de compatibilidad:
        - 'adminpage', 'owner', 'founder' cuentan como 'admin'
        - 'manager' cuenta como 'smod'
        - 'p-helper' cuenta como 'helper'
        """
        if 'admin' in roles and self.role in ('adminpage', 'owner', 'founder'):
            return True
        if 'smod' in roles and self.role == 'manager':
            return True
        if 'helper' in roles and self.role == 'p-helper':
            return True
        return self.role in roles
    
    def can_edit(self):
        """Indica si el usuario puede editar mods."""
        return self.role in ('smod', 'admin', 'adminpage', 'owner', 'founder', 'manager')
    
    def is_admin(self):
        """Verifica si el usuario es admin, adminpage, owner o founder."""
        return self.role in ('admin', 'adminpage', 'owner', 'founder')


class Mod(db.Model):
    """Modelo de mod con estado, categoría y alias."""
    
    __tablename__ = 'mods'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='prohibido')  # prohibido, permitido
    category = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    description = db.Column(db.Text)
    aliases = db.Column(db.Text)  # Guardado como string separada por comas
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<Mod {self.name} ({self.status})>'
    
    def get_aliases_list(self):
        """Devuelve los alias como lista."""
        if not self.aliases:
            return []
        return [a.strip() for a in self.aliases.split(',') if a.strip()]
    
    def set_aliases_list(self, alias_list):
        """Setea los alias desde una lista."""
        if isinstance(alias_list, list):
            self.aliases = ', '.join([str(a).strip() for a in alias_list if a])
        else:
            self.aliases = str(alias_list) if alias_list else ''
    
    def to_dict(self):
        """Convert mod to dictionary (compatible with old JSON format)."""
        return {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'category': self.category,
            'platform': self.platform,
            'description': self.description,
            'alias': self.get_aliases_list(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class LoginAttempt(db.Model):
    """Modelo para registrar intentos de login fallidos por IP y usuario."""
    
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)  # IPv4 and IPv6
    username = db.Column(db.String(80), nullable=False)
    attempts = db.Column(db.Integer, default=1, nullable=False)
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    block_count = db.Column(db.Integer, default=0, nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<LoginAttempt {self.ip_address} - {self.username} ({self.attempts})>'

# ===================== MODALIDAD =====================
class Modalidad(db.Model):
    __tablename__ = 'modalidades'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    nota = db.Column(db.Text)  # Nota importante para la modalidad (opcional)
    orden = db.Column(db.Integer, nullable=False, default=0, index=True)
    # Puedes agregar más campos si lo necesitas

    def __repr__(self):
        return f'<Modalidad {self.nombre}>'


# ===================== GUIA SANCIONES: MODALIDAD (SEPARADA) =====================
class GuiaSancionesModalidad(db.Model):
    __tablename__ = 'guia_sanciones_modalidades'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(120), unique=True, nullable=False)
    orden = db.Column(db.Integer, nullable=False, default=0, index=True)

    def __repr__(self):
        return f'<GuiaSancionesModalidad {self.nombre}>'


# ===================== GUIA SANCIONES: SANCION =====================
class GuiaSancion(db.Model):
    __tablename__ = 'guia_sanciones_sanciones'
    id = db.Column(db.Integer, primary_key=True)
    modalidad_id = db.Column(db.Integer, db.ForeignKey('guia_sanciones_modalidades.id'), nullable=False, index=True)
    texto = db.Column(db.Text, nullable=False)
    orden = db.Column(db.Integer, nullable=False, default=0, index=True)

    modalidad = db.relationship(
        'GuiaSancionesModalidad',
        backref=db.backref('sanciones', lazy=True, cascade='all, delete-orphan'),
    )

    def __repr__(self):
        return f'<GuiaSancion {self.modalidad_id} #{self.orden}>'


# ===================== REGLA =====================
class Regla(db.Model):
    __tablename__ = 'reglas'
    id = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.Text, nullable=False)
    ejemplo = db.Column(db.Text)  # Ejemplo opcional para aclarar la regla
    modalidad_id = db.Column(db.Integer, db.ForeignKey('modalidades.id'), nullable=False)
    orden = db.Column(db.Integer, default=0)  # Para ordenar reglas opcionalmente

    modalidad = db.relationship('Modalidad', backref=db.backref('reglas', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f'<Regla {self.descripcion[:30]}... (Modalidad {self.modalidad_id})>'


# ===================== COMANDOS STAFF =====================
class Comando(db.Model):
    __tablename__ = 'comandos_staff'
    id = db.Column(db.Integer, primary_key=True)
    rango = db.Column(db.String(64), nullable=False, index=True)
    nombre = db.Column(db.String(200), nullable=False)
    descripcion = db.Column(db.Text)    # descripción corta
    informacion = db.Column(db.Text)    # descripción larga / información
    orden = db.Column(db.Integer, default=0, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'rango': self.rango,
            'name': self.nombre,
            'short': self.descripcion,
            'long': self.informacion,
            'orden': self.orden,
        }

    def __repr__(self):
        return f'<Comando {self.rango} {self.nombre}>'


# ===================== SS SESSION (Login con 2FA temporal) =====================
class SSSession(db.Model):
    __tablename__ = 'ss_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    
    user = db.relationship('User', backref=db.backref('ss_sessions', lazy=True, cascade='all, delete-orphan'))
    
    def is_valid(self):
        """Verifica si el token no expiró."""
        return datetime.utcnow() < self.expires_at
    
    def __repr__(self):
        return f'<SSSession user={self.user_id} expires={self.expires_at}>'


# ===================== SS LINKS =====================
class SSLink(db.Model):
    __tablename__ = 'ss_links'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    icon = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<SSLink {self.name}>'
