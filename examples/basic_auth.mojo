"""Basic JWT authentication example."""
from mojo_auth import JwtValidator, JwtConfig, Claims

fn main() raises:
    # Configure JWT validator
    var config = JwtConfig(
        secret="your-secret-key-min-32-chars-long!",
        issuer="my-app",
        expiration_minutes=60,
    )
    var validator = JwtValidator(config)
    
    # Generate a token
    var roles = List[String]()
    roles.append("user")
    roles.append("admin")
    var token = validator.generate("user123", roles)
    print("Generated token:", token[:50], "...")
    
    # Validate the token
    var claims = validator.validate(token)
    if claims.is_valid():
        print("User ID:", claims.user_id)
        print("Has admin role:", claims.has_role("admin"))
    else:
        print("Invalid token:", claims.error)
