// External-authentication enforcement policies (DESIGN.md §2.3).
//
// Decision contract: action `login`.
//   Allow (permit, no forbid matches) = normal login permitted (NOT forced).
//   Deny  (a forbid matches)          = external authentication is FORCED.
//
// Baseline: permit all login; client-specific `forbid` rules force external
// auth for risky conditions. Cedar's `forbid` always wins over `permit`.
//
// Authoring conventions (annotations, naming, adding new use cases):
// see ./README.md ("ポリシー定義ルール").

@id("allow-login")
@description("Baseline: permit all logins. Client-specific forbid rules below override this to force external auth for risky conditions.")
permit(principal, action == Action::"login", resource);

// a-client: force external auth for employees in dept "A*" over the internet.
// `@decision_context_<key>` annotations are returned to the PEP as the AuthZEN response
// `context` when this policy determines the decision (DESIGN.md §2.2).
@id("a-client-deny")
@description("a-client: force external auth for employees in dept A* arriving over the internet. Step up privileged-department access from untrusted routes.")
@decision_context_reason_user("External authentication is required for this access route.")
@decision_context_step_up("external-auth")
forbid(principal, action == Action::"login", resource == Client::"a-client")
when {
  principal has user_type && principal.user_type == "employee" &&
  principal has department && principal.department like "A*" &&
  context has access_route && context.access_route == "internet"
};

// b-client: force external auth for partners arriving over the internal route.
@id("b-client-deny")
@description("b-client: force external auth for partners arriving over the internal route.")
forbid(principal, action == Action::"login", resource == Client::"b-client")
when {
  principal has user_type && principal.user_type == "partner" &&
  context has access_route && context.access_route == "internal"
};

// -- requireMfa: step-up MFA enforcement -------------------------------------
//
// Same "enforcement family" as `login` (see ./README.md §2): baseline `permit`
// plus condition-specific `forbid` overrides, and `decision: false` is the
// "something extra happens" side.
//   Allow (permit, no forbid matches) = step-up MFA NOT required.
//   Deny  (a forbid matches)          = step-up MFA is REQUIRED.
// `@decision_context_step_up("mfa")` tells the PEP which mechanism to invoke
// (contrast `login`'s "external-auth"), so the same PEP field routes to the
// right flow per action.

@id("allow-no-mfa")
@description("Baseline for requireMfa: do not require step-up MFA. forbid rules below override this to require MFA for risky conditions.")
permit(principal, action == Action::"requireMfa", resource);

// Require step-up MFA for privileged-department employees on any client, unless
// they already reached a strong authentication level (authn_level "aal2").
@id("require-mfa-privileged")
@description("requireMfa: require step-up MFA for dept A* employees on any client, unless they already reached authn_level aal2. Protects privileged-department sessions with a second factor without re-prompting users who already stepped up.")
@decision_context_reason_user("Additional verification is required to continue.")
@decision_context_step_up("mfa")
forbid(principal, action == Action::"requireMfa", resource)
when {
  principal has user_type && principal.user_type == "employee" &&
  principal has department && principal.department like "A*"
}
unless {
  context has authn_level && context.authn_level == "aal2"
};
