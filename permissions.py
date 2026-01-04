"""
Permission system for RBAC (Role-Based Access Control)
Defines roles, permissions, and decorators for route protection
"""
from functools import wraps
from flask import jsonify, request
from flask_login import current_user
import json

# Role definitions
ROLE_ADMIN = 'admin'
ROLE_ANALYST = 'analyst'

# Permission mappings
PERMISSIONS = {
    ROLE_ADMIN: [
        'view_dashboard',
        'export_data',
        'manage_users',
        'view_audit_logs',
        'configure_system'
    ],
    ROLE_ANALYST: [
        'view_dashboard',
        'export_data'
    ]
}


def has_permission(user, permission):
    """Check if user has a specific permission"""
    if not user or not user.is_authenticated:
        return False
    
    user_role = getattr(user, 'role', ROLE_ANALYST)
    return permission in PERMISSIONS.get(user_role, [])


def role_required(roles):
    """
    Decorator to require specific roles for a route
    Usage: @role_required(['admin', 'analyst'])
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            user_role = getattr(current_user, 'role', ROLE_ANALYST)
            
            # If roles is a string, convert to list
            allowed_roles = roles if isinstance(roles, list) else [roles]
            
            if user_role not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_roles': allowed_roles,
                    'your_role': user_role
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required(permission):
    """
    Decorator to require specific permission for a route
    Usage: @permission_required('export_data')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not has_permission(current_user, permission):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_permission': permission
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr
