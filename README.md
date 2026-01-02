# mojo-auth

JWT authentication and RBAC for Mojo applications.

## Features

- **JwtValidator** - JWT token validation via PyJWT
- **JwtConfig** - Configurable JWT settings
- **Claims** - Parsed token claims with role helpers
- **RoleChecker** - Permission-based authorization
- **AuthMiddleware** - HTTP request authentication

## Installation

```bash
pixi add mojo-auth
pip install PyJWT  # Python dependency
```

## Quick Start

### JWT Validation

```mojo
from mojo_auth import JwtValidator, JwtConfig

# Configure validator
var config = JwtConfig(
    secret="your-secret-key",
    issuer="your-app",
    expiration_minutes=60,
)
var validator = JwtValidator(config)

# Validate token
var claims = validator.validate(token)
if claims.is_valid():
    print("User:", claims.user_id)
    print("Roles:", claims.roles)
else:
    print("Invalid:", claims.error)
```

### Token Generation

```mojo
from mojo_auth import JwtValidator, JwtConfig

var validator = JwtValidator(JwtConfig(secret="secret"))

# Generate token
var roles = List[String]()
roles.append("admin")
roles.append("user")
var token = validator.generate("user123", roles)
```

### Role Checking

```mojo
from mojo_auth import Claims

var claims = validator.validate(token)

# Check single role
if claims.has_role("admin"):
    allow_admin_access()

# Check any of multiple roles
var allowed_roles = List[String]()
allowed_roles.append("admin")
allowed_roles.append("moderator")
if claims.has_any_role(allowed_roles):
    allow_moderator_access()
```

### RBAC (Role-Based Access Control)

```mojo
from mojo_auth import RoleChecker

var checker = RoleChecker()

# Define permissions for roles
checker.add_permission("admin", "users:write")
checker.add_permission("admin", "users:read")
checker.add_permission("admin", "users:delete")
checker.add_permission("user", "users:read")
checker.add_permission("user", "profile:*")

# Check permission
if checker.has_permission(claims.roles, "users:write"):
    update_user()
```

### HTTP Middleware

```mojo
from mojo_auth import AuthMiddleware, require_auth, require_roles

var middleware = AuthMiddleware(validator)

fn handle_request(headers: Dict[String, String]) -> Response:
    # Require authentication
    var result = require_auth(headers, middleware)
    if not result.authenticated:
        return Response(401, result.error)

    # Access claims
    print("User:", result.claims.user_id)
    return Response(200, "OK")

fn admin_handler(headers: Dict[String, String]) -> Response:
    # Require admin role
    var required = List[String]()
    required.append("admin")
    var result = require_roles(headers, middleware, required)

    if not result.is_allowed():
        return Response(403, "Forbidden")

    return Response(200, "Admin access granted")
```

## Configuration

### JwtConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `secret` | required | HMAC secret key |
| `issuer` | "" | Expected token issuer |
| `audience` | "" | Expected token audience |
| `expiration_minutes` | 60 | Token expiration |

### AuthMiddleware

| Parameter | Default | Description |
|-----------|---------|-------------|
| `header_name` | "Authorization" | Header name |
| `token_prefix` | "Bearer " | Token prefix |

## Dependencies

Requires PyJWT:

```bash
pip install PyJWT
```

## Testing

```bash
pixi run test
```

## License

MIT
