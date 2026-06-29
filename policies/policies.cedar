// External-authentication enforcement policies (DESIGN.md §2.3).
//
// Decision contract: action `login`.
//   Allow (permit, no forbid matches) = normal login permitted (NOT forced).
//   Deny  (a forbid matches)          = external authentication is FORCED.
//
// Baseline: permit all login; client-specific `forbid` rules force external
// auth for risky conditions. Cedar's `forbid` always wins over `permit`.

@id("allow-login")
permit(principal, action == Action::"login", resource);

// a-client: force external auth for employees in dept "A*" over the internet.
@id("a-client-deny")
forbid(principal, action == Action::"login", resource == Client::"a-client")
when {
  principal has user_type && principal.user_type == "employee" &&
  principal has department && principal.department like "A*" &&
  context has access_route && context.access_route == "internet"
};

// b-client: force external auth for partners arriving over the internal route.
@id("b-client-deny")
forbid(principal, action == Action::"login", resource == Client::"b-client")
when {
  principal has user_type && principal.user_type == "partner" &&
  context has access_route && context.access_route == "internal"
};
