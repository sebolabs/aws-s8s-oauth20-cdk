/**
 * Access_Token JWT claims validation — pure module, no AWS SDK calls.
 *
 * Validates the decoded JWT payload claims of an Access_Token after
 * signature verification has already passed.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 6.6, 6.7, 6.8, 6.9, 10.2, 10.3, 10.4, 10.7
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AccessTokenPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  jti?: string;
  scope?: string;
  [key: string]: unknown;
}

export interface AccessTokenValidationSuccess {
  valid: true;
}

export interface AccessTokenValidationFailure {
  valid: false;
  failedClaim: string;
  reason: string;
}

export type AccessTokenValidationResult = AccessTokenValidationSuccess | AccessTokenValidationFailure;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate the decoded JWT payload claims of an Access_Token.
 *
 * Checks are applied in the following order:
 * 1. `exp` must not be expired beyond clock skew tolerance (Requirements 6.6, 10.2, 10.7)
 * 2. `scope` must contain `appointments:read` (Requirement 6.7)
 * 3. `iss` must equal `tokenEndpointUrl` (Requirement 6.8)
 * 4. `aud` must equal or contain `appointmentsEndpointUrl` (Requirement 6.8)
 *
 * @param payload                 - Decoded JWT payload object
 * @param tokenEndpointUrl        - Expected issuer (Token_Endpoint URL)
 * @param appointmentsEndpointUrl - Expected audience (Appointments_Endpoint URL)
 * @param clockSkewSeconds        - Clock skew tolerance in seconds (default 10)
 * @returns AccessTokenValidationSuccess if all checks pass, or AccessTokenValidationFailure with details
 */
export function validateAccessTokenClaims(
  payload: AccessTokenPayload,
  tokenEndpointUrl: string,
  appointmentsEndpointUrl: string,
  clockSkewSeconds: number = 10,
): AccessTokenValidationResult {
  // 1. exp must not be expired beyond clock skew (Requirements 6.6, 10.2, 10.7)
  if (payload.exp === undefined || payload.exp === null) {
    return {
      valid: false,
      failedClaim: 'exp',
      reason: 'exp claim must be present',
    };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (nowSeconds - payload.exp > clockSkewSeconds) {
    return {
      valid: false,
      failedClaim: 'exp',
      reason: `Access_Token has expired (exp: ${payload.exp}, now: ${nowSeconds}, skew: ${clockSkewSeconds}s)`,
    };
  }

  // 2. scope must contain "appointments:read" (Requirement 6.7)
  if (!scopeContains(payload.scope, 'appointments:read')) {
    return {
      valid: false,
      failedClaim: 'scope',
      reason: 'scope claim must contain "appointments:read"',
    };
  }

  // 3. iss must equal tokenEndpointUrl (Requirement 6.8)
  if (payload.iss !== tokenEndpointUrl) {
    return {
      valid: false,
      failedClaim: 'iss',
      reason: `iss claim must equal Token_Endpoint URL "${tokenEndpointUrl}", got "${String(payload.iss)}"`,
    };
  }

  // 4. aud must equal or contain appointmentsEndpointUrl (Requirement 6.8)
  if (!audContains(payload.aud, appointmentsEndpointUrl)) {
    return {
      valid: false,
      failedClaim: 'aud',
      reason: `aud claim must equal or contain Appointments_Endpoint URL "${appointmentsEndpointUrl}"`,
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Check whether the `scope` claim contains the given scope value.
 * The `scope` claim is a space-delimited string of scope values.
 */
function scopeContains(scope: string | undefined, requiredScope: string): boolean {
  if (scope === undefined || scope === null || typeof scope !== 'string') {
    return false;
  }
  const scopes = scope.split(' ');
  return scopes.includes(requiredScope);
}

/**
 * Check whether the `aud` claim equals or contains the given URL.
 * The `aud` claim can be either a single string or an array of strings.
 */
function audContains(aud: string | string[] | undefined, url: string): boolean {
  if (aud === undefined || aud === null) {
    return false;
  }
  if (typeof aud === 'string') {
    return aud === url;
  }
  if (Array.isArray(aud)) {
    return aud.includes(url);
  }
  return false;
}
