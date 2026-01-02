"""
Mojo Auth Library

JWT authentication and RBAC via Python interop (PyJWT).

Usage:
    from mojo_auth import JwtValidator, JwtConfig

    var config = JwtConfig(secret="your-secret", issuer="your-app")
    var validator = JwtValidator(config)

    # Validate token
    var claims = validator.validate(token)
    print(claims.user_id, claims.roles)

    # Generate token
    var token = validator.generate("user123", ["admin", "user"])
"""

from .jwt import JwtValidator, JwtConfig, Claims
from .rbac import RoleChecker, Permission
from .middleware import AuthMiddleware, require_auth, require_roles
