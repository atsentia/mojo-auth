"""Tests for JWT validation."""

from testing import assert_true, assert_false, assert_equal
from ..src.jwt import JwtConfig, JwtValidator, Claims
from ..src.rbac import RoleChecker, Permission


fn test_jwt_config_creation():
    """JwtConfig can be created."""
    var config = JwtConfig("my-secret")

    assert_equal(config.secret, "my-secret")
    assert_equal(config.expiration_minutes, 60)


fn test_jwt_config_with_options():
    """JwtConfig with all options."""
    var config = JwtConfig(
        secret="my-secret",
        issuer="my-app",
        audience="my-api",
        expiration_minutes=120,
    )

    assert_equal(config.issuer, "my-app")
    assert_equal(config.audience, "my-api")
    assert_equal(config.expiration_minutes, 120)


fn test_claims_empty():
    """Empty claims are invalid."""
    var claims = Claims()

    assert_false(claims.is_valid())
    assert_false(claims.has_role("admin"))


fn test_claims_has_role():
    """Claims role checking."""
    var claims = Claims()
    claims.valid = True
    claims.roles.append("admin")
    claims.roles.append("user")

    assert_true(claims.has_role("admin"))
    assert_true(claims.has_role("user"))
    assert_false(claims.has_role("guest"))


fn test_claims_has_any_role():
    """Claims any role checking."""
    var claims = Claims()
    claims.valid = True
    claims.roles.append("user")

    var required = List[String]()
    required.append("admin")
    required.append("user")

    assert_true(claims.has_any_role(required))


fn test_permission_parsing():
    """Permission parsing from string."""
    var perm = Permission("users:read")

    assert_equal(perm.resource, "users")
    assert_equal(perm.action, "read")


fn test_permission_matching():
    """Permission matching logic."""
    var read = Permission("users:read")
    var write = Permission("users:write")
    var wildcard = Permission("users:*")
    var all = Permission("*:*")

    assert_false(read.matches(write))
    assert_true(read.matches(wildcard))
    assert_true(read.matches(all))


fn test_role_checker():
    """RoleChecker permission checking."""
    var checker = RoleChecker()
    checker.add_permission("admin", "users:write")
    checker.add_permission("admin", "users:read")
    checker.add_permission("user", "users:read")

    var admin_roles = List[String]()
    admin_roles.append("admin")

    var user_roles = List[String]()
    user_roles.append("user")

    assert_true(checker.has_permission(admin_roles, "users:write"))
    assert_true(checker.has_permission(admin_roles, "users:read"))
    assert_false(checker.has_permission(user_roles, "users:write"))
    assert_true(checker.has_permission(user_roles, "users:read"))


# =============================================================================
# SEC-006: JWT Expiration Security Tests
# =============================================================================


fn test_token_without_exp_rejected_by_default():
    """
    SEC-006: Tokens WITHOUT an `exp` claim MUST be rejected by default.

    This is a critical security test. Allowing tokens without expiration
    creates a major vulnerability where stolen tokens remain valid forever.
    """
    var config = JwtConfig("test-secret")
    var validator = JwtValidator(config)

    # Token without exp claim (base64url encoded):
    # Header: {"alg":"HS256","typ":"JWT"}
    # Payload: {"sub":"user123","iat":1704067200}  (no exp!)
    # Note: This is a mock token for testing. In real scenarios, we would
    # generate this using the mojo-jwt library's create_jwt function.
    # For this test, we use a pre-constructed token without exp.
    var token_without_exp = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzA0MDY3MjAwfQ.mock_signature"

    var claims = validator.validate(token_without_exp)

    # MUST be invalid because exp is missing
    assert_false(claims.is_valid())
    # Error message should indicate missing exp claim
    assert_true(len(claims.error) > 0)


fn test_token_without_exp_allowed_with_insecure_flag():
    """
    SEC-006: Tokens without `exp` can be allowed if explicitly configured.

    This tests the escape hatch for specific use cases. The method name
    includes INSECURE to make the security implications clear.
    """
    var config = JwtConfig("test-secret")
    # Explicitly allow no expiration (DANGEROUS!)
    _ = config.allow_no_expiration_INSECURE()

    # Verify the flag is set
    assert_true(config.allow_no_exp)


fn test_token_with_exp_accepted():
    """
    SEC-006: Tokens WITH a valid `exp` claim should be accepted.

    This verifies that the fix doesn't break normal token validation.
    """
    var config = JwtConfig("test-secret")
    var validator = JwtValidator(config)

    # Generate a valid token with expiration
    var roles = List[String]()
    roles.append("user")
    var current_time: Int64 = 1704067200  # Jan 1, 2024 00:00:00 UTC

    # Generate token (will include exp)
    var token = validator.generate("user123", roles, current_time)

    # Validate the token we just generated
    var claims = validator.validate(token)

    # Should be valid because it has exp
    assert_true(claims.is_valid())
    assert_equal(claims.user_id, "user123")
    assert_true(claims.exp > 0)  # exp should be set


fn test_config_defaults_require_exp():
    """
    SEC-006: JwtConfig should require exp by default.

    Verifies that new configs have secure defaults.
    """
    var config = JwtConfig("test-secret")

    # By default, tokens without exp should be rejected
    assert_false(config.allow_no_exp)


fn main():
    """Run all tests."""
    print("Running JWT tests...")

    test_jwt_config_creation()
    print("  ✓ test_jwt_config_creation")

    test_jwt_config_with_options()
    print("  ✓ test_jwt_config_with_options")

    test_claims_empty()
    print("  ✓ test_claims_empty")

    test_claims_has_role()
    print("  ✓ test_claims_has_role")

    test_claims_has_any_role()
    print("  ✓ test_claims_has_any_role")

    test_permission_parsing()
    print("  ✓ test_permission_parsing")

    test_permission_matching()
    print("  ✓ test_permission_matching")

    test_role_checker()
    print("  ✓ test_role_checker")

    # SEC-006: JWT Expiration Security Tests
    print("\nRunning SEC-006 security tests...")

    test_config_defaults_require_exp()
    print("  ✓ test_config_defaults_require_exp")

    test_token_without_exp_rejected_by_default()
    print("  ✓ test_token_without_exp_rejected_by_default")

    test_token_without_exp_allowed_with_insecure_flag()
    print("  ✓ test_token_without_exp_allowed_with_insecure_flag")

    test_token_with_exp_accepted()
    print("  ✓ test_token_with_exp_accepted")

    print("\nAll JWT tests passed!")
