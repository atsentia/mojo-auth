"""
Authentication Middleware

Provides middleware for HTTP request authentication.

Example:
    var middleware = AuthMiddleware(validator)

    fn protected_handler(request: Request) -> Response:
        var claims = middleware.authenticate(request)
        if not claims.is_valid():
            return Response(401, "Unauthorized")
        # Handle authenticated request
"""

from .jwt import JwtValidator, Claims


struct AuthMiddleware:
    """HTTP authentication middleware."""

    var validator: JwtValidator
    """JWT validator."""

    var header_name: String
    """Header containing token (default: Authorization)."""

    var token_prefix: String
    """Token prefix (default: Bearer)."""

    fn __init__(out self, validator: JwtValidator):
        """Create middleware with validator."""
        self.validator = validator
        self.header_name = "Authorization"
        self.token_prefix = "Bearer "

    fn authenticate(self, headers: Dict[String, String]) -> Claims:
        """
        Authenticate request from headers.

        Args:
            headers: HTTP request headers.

        Returns:
            Claims if authenticated, invalid claims otherwise.
        """
        var claims = Claims()

        if self.header_name not in headers:
            claims.error = "Missing " + self.header_name + " header"
            return claims

        var auth_header = headers[self.header_name]

        # Check prefix
        if not auth_header.startswith(self.token_prefix):
            claims.error = "Invalid token format"
            return claims

        # Extract token
        var token = auth_header[len(self.token_prefix):]

        return self.validator.validate(token)

    fn get_token(self, headers: Dict[String, String]) -> String:
        """Extract token from headers."""
        if self.header_name not in headers:
            return ""

        var auth_header = headers[self.header_name]
        if not auth_header.startswith(self.token_prefix):
            return ""

        return auth_header[len(self.token_prefix):]


struct AuthResult:
    """Result of authentication check."""

    var authenticated: Bool
    """Whether request is authenticated."""

    var authorized: Bool
    """Whether request is authorized (has required roles)."""

    var claims: Claims
    """Extracted claims."""

    var error: String
    """Error message if failed."""

    fn __init__(out self):
        self.authenticated = False
        self.authorized = False
        self.claims = Claims()
        self.error = ""

    fn is_allowed(self) -> Bool:
        return self.authenticated and self.authorized


fn require_auth(headers: Dict[String, String], middleware: AuthMiddleware) -> AuthResult:
    """
    Require authentication.

    Args:
        headers: Request headers.
        middleware: Auth middleware.

    Returns:
        AuthResult with authentication status.
    """
    var result = AuthResult()
    var claims = middleware.authenticate(headers)

    if claims.is_valid():
        result.authenticated = True
        result.authorized = True
        result.claims = claims
    else:
        result.error = claims.error

    return result


fn require_roles(
    headers: Dict[String, String],
    middleware: AuthMiddleware,
    required_roles: List[String],
) -> AuthResult:
    """
    Require authentication and specific roles.

    Args:
        headers: Request headers.
        middleware: Auth middleware.
        required_roles: Required roles (any one).

    Returns:
        AuthResult with authorization status.
    """
    var result = require_auth(headers, middleware)

    if not result.authenticated:
        return result

    # Check roles
    result.authorized = result.claims.has_any_role(required_roles)
    if not result.authorized:
        result.error = "Insufficient permissions"

    return result
