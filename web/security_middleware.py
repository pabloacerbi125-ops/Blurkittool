"""
Sistema de bloqueo global anti-bot
Detecta IPs sospechosas y las bloquea en TODAS las rutas
"""
from flask import request, abort, jsonify
from functools import wraps
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class GlobalIPBlocker:
    """Gestiona bloqueo global de IPs sospechosas"""
    
    def __init__(self, storage='memory', redis_client=None):
        """
        storage: 'memory' o 'redis'
        redis_client: instancia de Redis (opcional, para producción)
        """
        self.storage = storage
        self.redis = redis_client
        
        # Almacenamiento en memoria (para desarrollo/testing)
        self.blacklist = {}  # {ip: {'expiry': timestamp, 'block_count': N}}
        self.suspicious_activity = {}  # {ip: {'429_count': N, 'last_reset': timestamp}}
        self.alerts = []  # Lista de alertas para admin (máx 100)
        
        # Configuración
        self.MAX_429_BEFORE_BLOCK = 400  # Después de 400 respuestas 429, bloqueo global
        self.BASE_BLOCK_MINUTES = 15  # Bloqueo base: 15 minutos
        self.SUSPICIOUS_RESET_MINUTES = 5  # Resetea contadores cada 5 min
        self.MAX_ALERTS = 100  # Máximo alertas en memoria
    
    def get_client_ip(self):
        """Obtiene IP real del cliente (detrás de proxy)"""
        # ProxyFix ya normaliza remote_addr, pero por si acaso
        return request.headers.get('X-Real-IP') or \
               request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or \
               request.remote_addr
    
    def is_blocked(self, ip=None):
        """Verifica si una IP está bloqueada globalmente"""
        if ip is None:
            ip = self.get_client_ip()
        
        if self.storage == 'redis' and self.redis:
            blocked = self.redis.get(f'blocked:{ip}')
            return blocked is not None
        else:
            # Limpia IPs expiradas
            now = datetime.now().timestamp()
            if ip in self.blacklist:
                if self.blacklist[ip]['expiry'] > now:
                    return True
                else:
                    del self.blacklist[ip]
            return False
    
    def block_ip(self, ip, duration_minutes=None, reason="Actividad sospechosa"):
        """Bloquea una IP globalmente por X minutos (progresivo: 15, 30, 45...)"""
        # Determina el contador de bloqueos previos
        block_count = 0
        if ip in self.blacklist:
            block_count = self.blacklist[ip].get('block_count', 0)
        
        # Incrementa contador
        block_count += 1
        
        # Calcula duración progresiva: 15 * block_count (15, 30, 45, 60...)
        if duration_minutes is None:
            duration_minutes = self.BASE_BLOCK_MINUTES * block_count
        
        expiry = datetime.now() + timedelta(minutes=duration_minutes)
        
        if self.storage == 'redis' and self.redis:
            # Guarda contador en Redis
            self.redis.setex(
                f'blocked:{ip}',
                duration_minutes * 60,
                str(block_count)
            )
            self.redis.setex(
                f'block_count:{ip}',
                duration_minutes * 60,
                str(block_count)
            )
        else:
            self.blacklist[ip] = {
                'expiry': expiry.timestamp(),
                'block_count': block_count
            }
        
        # Genera alerta para admin
        self._add_alert(ip, reason, duration_minutes, block_count)
        
        logger.warning(f"🚫 IP {ip} bloqueada globalmente por {duration_minutes} min (bloqueo #{block_count})")
    
    def track_429(self, ip=None):
        """Registra un 429 y bloquea si supera el límite"""
        if ip is None:
            ip = self.get_client_ip()
        
        now = datetime.now()
        
        if ip not in self.suspicious_activity:
            self.suspicious_activity[ip] = {
                '429_count': 0,
                'last_reset': now
            }
        
        activity = self.suspicious_activity[ip]
        
        # Resetea contadores si pasó el tiempo
        if (now - activity['last_reset']).seconds > self.SUSPICIOUS_RESET_MINUTES * 60:
            activity['429_count'] = 0
            activity['last_reset'] = now
        
        # Incrementa contador
        activity['429_count'] += 1
        
        logger.info(f"⚠️  IP {ip} recibió 429 ({activity['429_count']}/{self.MAX_429_BEFORE_BLOCK})")
        
        # Si supera el límite, bloqueo global
        if activity['429_count'] >= self.MAX_429_BEFORE_BLOCK:
            self.block_ip(ip)
            # Limpia el tracking para esta IP
            del self.suspicious_activity[ip]
            return True
        
        return False
    
    def _add_alert(self, ip, reason, duration_minutes, block_count):
        """Agrega alerta para panel de admin"""
        alert = {
            'timestamp': datetime.now(),
            'ip': ip,
            'reason': reason,
            'duration_minutes': duration_minutes,
            'block_count': block_count,
            'level': 'warning' if block_count == 1 else 'danger'
        }
        self.alerts.insert(0, alert)  # Más recientes primero
        
        # Limita a MAX_ALERTS
        if len(self.alerts) > self.MAX_ALERTS:
            self.alerts = self.alerts[:self.MAX_ALERTS]
    
    def get_alerts(self, limit=50):
        """Obtiene alertas recientes para admin"""
        return self.alerts[:limit]
    
    def get_blocked_ips(self):
        """Obtiene lista de IPs bloqueadas con detalles"""
        blocked = []
        now = datetime.now().timestamp()
        
        for ip, data in self.blacklist.items():
            if data['expiry'] > now:
                remaining = int((data['expiry'] - now) / 60)
                blocked.append({
                    'ip': ip,
                    'block_count': data['block_count'],
                    'time_remaining': remaining,
                    'expires_at': datetime.fromtimestamp(data['expiry'])
                })
        
        return blocked
    
    def unblock_ip(self, ip):
        """Desbloquea manualmente una IP (para admin)"""
        if self.storage == 'redis' and self.redis:
            self.redis.delete(f'blocked:{ip}')
            self.redis.delete(f'block_count:{ip}')
        else:
            if ip in self.blacklist:
                del self.blacklist[ip]
        
        logger.info(f"✅ IP {ip} desbloqueada manualmente")


# Instancia global (inicializar en app.py)
blocker = None

def init_blocker(app, redis_client=None):
    """Inicializa el bloqueador global"""
    global blocker
    storage = 'redis' if redis_client else 'memory'
    blocker = GlobalIPBlocker(storage=storage, redis_client=redis_client)
    
    # Middleware: bloquea IPs en blacklist ANTES de cualquier ruta
    @app.before_request
    def check_global_blacklist():
        ip = blocker.get_client_ip()
        if blocker.is_blocked(ip):
            logger.warning(f"🚫 Acceso bloqueado globalmente para IP {ip} en {request.path}")
            abort(403, description="Tu IP ha sido bloqueada temporalmente por actividad sospechosa. Intenta de nuevo más tarde.")
    
    # After request: trackea 429 para bloqueo automático
    @app.after_request
    def track_rate_limit_hits(response):
        if response.status_code == 429:
            ip = blocker.get_client_ip()
            was_blocked = blocker.track_429(ip)
            if was_blocked:
                # La próxima petición será bloqueada con 403
                logger.warning(f"🔒 IP {ip} alcanzó el límite de 429, bloqueada globalmente")
        return response
    
    logger.info(f"✅ GlobalIPBlocker inicializado (storage: {storage})")
    return blocker


def require_not_blocked(f):
    """Decorator adicional para rutas críticas (opcional)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if blocker and blocker.is_blocked():
            abort(403, description="Acceso bloqueado por actividad sospechosa")
        return f(*args, **kwargs)
    return decorated_function
