"""
Role-Based Access Control (RBAC)

Provides role and permission management.

Example:
    var checker = RoleChecker()
    checker.add_permission("admin", "users:write")
    checker.add_permission("admin", "users:read")
    checker.add_permission("user", "users:read")

    if checker.has_permission(claims.roles, "users:write"):
        allow_write()
"""


@value
struct Permission:
    """Represents a permission."""

    var resource: String
    """Resource name (e.g., "users")."""

    var action: String
    """Action on resource (e.g., "read", "write")."""

    fn __init__(out self, permission: String):
        """Parse permission from "resource:action" format."""
        var parts = permission.split(":")
        if len(parts) == 2:
            self.resource = parts[0]
            self.action = parts[1]
        else:
            self.resource = permission
            self.action = "*"

    fn matches(self, other: Permission) -> Bool:
        """Check if this permission matches another."""
        # Wildcard matches everything
        if self.resource == "*" or other.resource == "*":
            return True
        if self.resource != other.resource:
            return False
        if self.action == "*" or other.action == "*":
            return True
        return self.action == other.action

    fn __str__(self) -> String:
        return self.resource + ":" + self.action


struct RoleChecker:
    """Role and permission checker."""

    var role_permissions: Dict[String, List[Permission]]
    """Mapping of role to permissions."""

    fn __init__(out self):
        """Create empty role checker."""
        self.role_permissions = Dict[String, List[Permission]]()

    fn add_role(inout self, role: String):
        """Add a role with no permissions."""
        if role not in self.role_permissions:
            self.role_permissions[role] = List[Permission]()

    fn add_permission(inout self, role: String, permission: String):
        """Add permission to role."""
        if role not in self.role_permissions:
            self.role_permissions[role] = List[Permission]()

        self.role_permissions[role].append(Permission(permission))

    fn has_permission(self, roles: List[String], permission: String) -> Bool:
        """
        Check if any role has the required permission.

        Args:
            roles: User's roles.
            permission: Required permission.

        Returns:
            True if user has permission.
        """
        var required = Permission(permission)

        for role in roles:
            if role in self.role_permissions:
                for perm in self.role_permissions[role]:
                    if perm.matches(required):
                        return True

        return False

    fn has_all_permissions(self, roles: List[String], permissions: List[String]) -> Bool:
        """Check if user has all required permissions."""
        for perm in permissions:
            if not self.has_permission(roles, perm):
                return False
        return True

    fn has_any_permission(self, roles: List[String], permissions: List[String]) -> Bool:
        """Check if user has any of the required permissions."""
        for perm in permissions:
            if self.has_permission(roles, perm):
                return True
        return False

    fn get_permissions(self, role: String) -> List[Permission]:
        """Get all permissions for a role."""
        if role in self.role_permissions:
            return self.role_permissions[role]
        return List[Permission]()


# Common role definitions
struct Roles:
    """Common role names."""

    alias ADMIN: String = "admin"
    alias USER: String = "user"
    alias GUEST: String = "guest"
    alias SERVICE: String = "service"


# Helper functions
fn require_role(roles: List[String], required: String) raises:
    """Raise error if role not present."""
    for role in roles:
        if role == required:
            return
    raise Error("Required role not found: " + required)


fn require_any_role(roles: List[String], required: List[String]) raises:
    """Raise error if none of the roles are present."""
    for req in required:
        for role in roles:
            if role == req:
                return
    raise Error("None of the required roles found")
