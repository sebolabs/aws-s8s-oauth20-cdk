/**
 * Scope validation — pure function, no AWS SDK calls.
 *
 * Validates that a requested OAuth 2.0 scope is a subset of the client's
 * allowed scopes from the Client_Registry.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 5.6
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScopeValidationResult =
  | { valid: true; grantedScope: string }
  | { valid: false };

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate that every scope in `requestedScope` is present in `allowedScopes`.
 *
 * Both parameters are space-delimited scope strings (e.g. "appointments:read").
 *
 * - If `requestedScope` is empty/undefined/blank, all `allowedScopes` are granted.
 * - If every requested scope is found in `allowedScopes`, returns `{ valid: true, grantedScope }`.
 * - If any requested scope is not in `allowedScopes`, returns `{ valid: false }`.
 *
 * @param requestedScope  - Space-delimited string of requested scope values (may be undefined/empty)
 * @param allowedScopes   - Space-delimited string of allowed scope values from Client_Registry
 */
export function validateScope(
  requestedScope: string | undefined,
  allowedScopes: string,
): ScopeValidationResult {
  const allowedSet = new Set(
    allowedScopes
      .split(' ')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );

  // If no scope requested, grant all allowed scopes
  if (!requestedScope || requestedScope.trim().length === 0) {
    return { valid: true, grantedScope: [...allowedSet].join(' ') };
  }

  const requestedList = requestedScope
    .split(' ')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  // Check that every requested scope is in the allowed set
  for (const scope of requestedList) {
    if (!allowedSet.has(scope)) {
      return { valid: false };
    }
  }

  // Granted scope is the validated requested scope (intersection with allowed)
  return { valid: true, grantedScope: requestedList.join(' ') };
}
