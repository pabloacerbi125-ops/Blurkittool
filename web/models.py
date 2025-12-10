"""Database models for BlurkitModsTool.

Defines User and Mod models with SQLAlchemy.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model with role-based permissions."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='helper')  # helper, mod, smod, admin
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'
    
    def has_role(self, *roles):
        """Check if user has any of the specified roles."""
        return self.role in roles
    
    def can_edit(self):
        """Check if user can edit mods."""
        return self.role in ('smod', 'admin')
    
    def is_admin(self):
        """Check if user is admin."""
        return self.role == 'admin'


class Mod(db.Model):
    """Mod model with status, category, and aliases."""
    
    __tablename__ = 'mods'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='prohibido')  # prohibido, permitido
    category = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    description = db.Column(db.Text)
    aliases = db.Column(db.Text)  # Stored as comma-separated string
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f'<Mod {self.name} ({self.status})>'
    
    def get_aliases_list(self):
        """Get aliases as a list."""
        if not self.aliases:
            return []
        return [a.strip() for a in self.aliases.split(',') if a.strip()]
    
    def set_aliases_list(self, alias_list):
        """Set aliases from a list."""
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
