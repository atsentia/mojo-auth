"""
JWT Validation using Pure Mojo

Provides JWT token validation and generation using the pure Mojo mojo-jwt library.
No Python interop required!

SECURITY NOTE: By default, tokens WITHOUT an `exp` (expiration) claim are REJECTED.
This is a critical security measure to prevent tokens from being valid indefinitely.
If you need to allow tokens without expiration (NOT RECOMMENDED), use the
`allow_no_expiration_INSECURE()` method on JwtConfig with extreme caution.

Example:
    var config = JwtConfig(secret="my-secret")
    var validator = JwtValidator(config)

    var claims = validator.validate(token)
    if claims.is_valid():
        print("User:", claims.user_id)
"""

# Pure Mojo JWT - no Python required!
from ...mojo_jwt.src import (
    validate as jwt_validate,
    ValidationOptions,
    parse_jwt,
    create_jwt,
    JWTHeader,
    Claims as JWTClaims,
)


@value
struct JwtConfig:
    """JWT configuration.

    SECURITY NOTE: By default, tokens WITHOUT an `exp` claim are REJECTED.
    This prevents tokens from being valid indefinitely, which is a critical
    security vulnerability. Use `allow_no_expiration_INSECURE()` only if you
    fully understand the risks and have a separate token revocation mechanism.
    """

    var secret: String
    """Secret key for HMAC algorithms."""

    var issuer: String
    """Expected token issuer (optional)."""

    var audience: String
    """Expected token audience (optional)."""

    var algorithms: List[String]
    """Allowed algorithms (default: HS256)."""

    var expiration_minutes: Int
    """Token expiration time for generation."""

    var allow_no_exp: Bool
    """INSECURE: If True, allow tokens without exp claim (default: False)."""

    fn __init__(out self, secret: String):
        """Create config with secret only.

        By default, tokens without an `exp` claim are REJECTED for security.
        """
        self.secret = secret
        self.issuer = ""
        self.audience = ""
        self.algorithms = List[String]()
        self.algorithms.append("HS256")
        self.expiration_minutes = 60
        self.allow_no_exp = False

    fn __init__(
        inout self,
        secret: String,
        issuer: String = "",
        audience: String = "",
        expiration_minutes: Int = 60,
    ):
        """Create config with all options.

        By default, tokens without an `exp` claim are REJECTED for security.
        """
        self.secret = secret
        self.issuer = issuer
        self.audience = audience
        self.algorithms = List[String]()
        self.algorithms.append("HS256")
        self.expiration_minutes = expiration_minutes
        self.allow_no_exp = False

    fn allow_no_expiration_INSECURE(inout self) -> Self:
        """
        Allow tokens WITHOUT an `exp` claim to be valid.

        SECURITY WARNING: THIS IS EXTREMELY DANGEROUS!

        Enabling this option allows tokens to be valid FOREVER. An attacker
        who obtains such a token has permanent access that cannot be revoked
        through expiration. This creates serious security risks:

        1. Stolen tokens grant permanent unauthorized access
        2. No automatic session timeout protection
        3. Token rotation/revocation becomes impossible without blocklists
        4. Violates security best practices (OWASP, NIST)

        ONLY use this if you have a very specific use case AND:
        - Implement a separate token revocation mechanism (blocklist/allowlist)
        - Have short-lived contexts where tokens are immediately invalidated
        - Are in a testing/development environment with no real user data

        For production systems, ALWAYS require expiration claims.
        """
        self.allow_no_exp = True
        return self


@value
struct Claims:
    """Parsed JWT claims."""

    var user_id: String
    """User identifier from token."""

    var roles: List[String]
    """User roles from token."""

    var exp: Int
    """Expiration timestamp."""

    var iat: Int
    """Issued-at timestamp."""

    var valid: Bool
    """Whether claims are valid."""

    var error: String
    """Error message if invalid."""

    fn __init__(out self):
        """Create empty claims."""
        self.user_id = ""
        self.roles = List[String]()
        self.exp = 0
        self.iat = 0
        self.valid = False
        self.error = ""

    fn is_valid(self) -> Bool:
        """Check if claims are valid."""
        return self.valid

    fn has_role(self, role: String) -> Bool:
        """Check if user has specific role."""
        for r in self.roles:
            if r == role:
                return True
        return False

    fn has_any_role(self, roles: List[String]) -> Bool:
        """Check if user has any of the specified roles."""
        for required in roles:
            for user_role in self.roles:
                if required == user_role:
                    return True
        return False


struct JwtValidator:
    """JWT token validator using pure Mojo mojo-jwt library."""

    var config: JwtConfig
    """Validation configuration."""

    fn __init__(out self, config: JwtConfig):
        """Create validator with configuration."""
        self.config = config

    fn validate(self, token: String) -> Claims:
        """
        Validate JWT token and extract claims.

        SECURITY: By default, tokens WITHOUT an `exp` claim are REJECTED.
        Use `JwtConfig.allow_no_expiration_INSECURE()` only if you have a
        specific use case and understand the risks.

        NOTE: For time-based validation (exp/nbf checks), use `validate_with_time()`
        which accepts the current timestamp. This method only validates token
        structure, signature, and requires exp claim presence.

        Args:
            token: JWT token string.

        Returns:
            Claims with validation result.
        """
        var claims = Claims()

        # Build validation options
        var options = ValidationOptions(self.config.secret)

        # Allow tokens without exp only if explicitly configured (INSECURE)
        if self.config.allow_no_exp:
            options = options.allow_no_expiration_INSECURE()

        # Skip time-based validation in this method (use validate_with_time for that)
        # BUT still require exp claim to be present by default
        options = options.skip_exp_validation().skip_nbf_validation()

        if len(self.config.issuer) > 0:
            options = options.require_issuer(self.config.issuer)
        if len(self.config.audience) > 0:
            options = options.require_audience(self.config.audience)

        # Validate token
        var result = jwt_validate(token, options)

        if result.is_err():
            claims.valid = False
            claims.error = str(result.error())
            return claims

        var validated = result.value()
        var jwt_claims = validated.claims()

        # Extract claims
        claims.user_id = jwt_claims.sub if jwt_claims.has_sub else ""
        claims.exp = int(jwt_claims.exp) if jwt_claims.has_exp else 0
        claims.iat = int(jwt_claims.iat) if jwt_claims.has_iat else 0

        # Note: roles would need custom claim parsing
        # For now, roles require JSON payload parsing
        claims.valid = True

        return claims

    fn validate_with_time(self, token: String, current_time: Int64) -> Claims:
        """
        Validate JWT token with time-based checks.

        SECURITY: By default, tokens WITHOUT an `exp` claim are REJECTED.
        Use `JwtConfig.allow_no_expiration_INSECURE()` only if you have a
        specific use case and understand the risks.

        Args:
            token: JWT token string.
            current_time: Current Unix timestamp for exp/nbf validation.

        Returns:
            Claims with validation result.
        """
        var claims = Claims()

        # Build validation options with time
        var options = ValidationOptions(self.config.secret)
        options = options.with_current_time(current_time)

        # Allow tokens without exp only if explicitly configured (INSECURE)
        if self.config.allow_no_exp:
            options = options.allow_no_expiration_INSECURE()

        if len(self.config.issuer) > 0:
            options = options.require_issuer(self.config.issuer)
        if len(self.config.audience) > 0:
            options = options.require_audience(self.config.audience)

        # Validate token
        var result = jwt_validate(token, options)

        if result.is_err():
            claims.valid = False
            claims.error = str(result.error())
            return claims

        var validated = result.value()
        var jwt_claims = validated.claims()

        # Extract claims
        claims.user_id = jwt_claims.sub if jwt_claims.has_sub else ""
        claims.exp = int(jwt_claims.exp) if jwt_claims.has_exp else 0
        claims.iat = int(jwt_claims.iat) if jwt_claims.has_iat else 0
        claims.valid = True

        return claims

    fn generate(self, user_id: String, roles: List[String], current_time: Int64) -> String:
        """
        Generate JWT token.

        Args:
            user_id: User identifier.
            roles: User roles.
            current_time: Current Unix timestamp.

        Returns:
            JWT token string.
        """
        var header = JWTHeader("HS256", "JWT")
        var exp_time = current_time + Int64(self.config.expiration_minutes * 60)

        # Build claims JSON
        var claims_json = '{"sub":"' + user_id + '","user_id":"' + user_id + '"'
        claims_json += ',"iat":' + str(current_time)
        claims_json += ',"exp":' + str(exp_time)

        if len(self.config.issuer) > 0:
            claims_json += ',"iss":"' + self.config.issuer + '"'
        if len(self.config.audience) > 0:
            claims_json += ',"aud":"' + self.config.audience + '"'

        # Add roles as JSON array
        if len(roles) > 0:
            claims_json += ',"roles":['
            for i in range(len(roles)):
                if i > 0:
                    claims_json += ','
                claims_json += '"' + roles[i] + '"'
            claims_json += ']'

        claims_json += '}'

        return create_jwt(header, claims_json, self.config.secret)

    fn refresh(self, token: String, current_time: Int64) -> String:
        """Refresh token with new expiration."""
        var claims = self.validate(token)
        if not claims.is_valid():
            return ""  # Return empty on failure

        return self.generate(claims.user_id, claims.roles, current_time)
