/**
 * Client_Assertion JWT claims validation — pure module, no AWS SDK calls.
 *
 * Validates the decoded JWT payload claims of a Client_Assertion after
 * signature verification has already passed.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 2.9, 2.10, 2.11, 2.12, 2.13, 2.14, 2.15, 10.1, 10.3, 10.4, 10.5, 10.6
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AssertionPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  jti?: unknown;
  [key: string]: unknown;
}

export interface AssertionValidationSuccess {
  valid: true;
}

export interface AssertionValidationFailure {
  valid: false;
  failedClaim: string;
  error_description: string;
}

export type AssertionValidationResult = AssertionValidationSuccess | AssertionValidationFailure;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate the decoded JWT payload claims of a Client_Assertion.
 *
 * Checks are applied in the following order:
 * 1. `iss` must equal `clientId` (Requirement 2.9)
 * 2. `sub` must equal `clientId` (Requirement 2.10)
 * 3. `aud` must contain `tokenEndpointUrl` (Requirement 2.11)
 * 4. `exp` must not be expired beyond clock skew tolerance (Requirements 2.12, 10.1, 10.5, 10.6)
 * 5. `iat` must be present (Requirement 2.13)
 * 6. `jti` must be present and a non-empty string (Requirement 2.14)
 *
 * @param payload           - Decoded JWT payload object
 * @param clientId          - Expected client_id from the token request
 * @param tokenEndpointUrl  - The Token_Endpoint URL that must appear in `aud`
 * @param clockSkewSeconds  - Clock skew tolerance in seconds (default 10)
 * @returns AssertionValidationSuccess if all checks pass, or AssertionValidationFailure with details
 */
export function validateAssertionClaims(
  payload: AssertionPayload,
  clientId: string,
  tokenEndpointUrl: string,
  clockSkewSeconds: number = 10,
): AssertionValidationResult {
  // 1. iss must equal clientId (Requirement 2.9)
  if (payload.iss !== clientId) {
    return {
      valid: false,
      failedClaim: 'iss',
      error_description: `iss claim must equal client_id "${clientId}", got "${String(payload.iss)}"`,
    };
  }

  // 2. sub must equal clientId (Requirement 2.10)
  if (payload.sub !== clientId) {
    return {
      valid: false,
      failedClaim: 'sub',
      error_description: `sub claim must equal client_id "${clientId}", got "${String(payload.sub)}"`,
    };
  }

  // 3. aud must contain tokenEndpointUrl (Requirement 2.11)
  if (!audContains(payload.aud, tokenEndpointUrl)) {
    return {
      valid: false,
      failedClaim: 'aud',
      error_description: `aud claim must contain token endpoint URL "${tokenEndpointUrl}"`,
    };
  }

  // 4. exp must not be expired beyond clock skew (Requirements 2.12, 10.1, 10.5, 10.6)
  if (payload.exp === undefined || payload.exp === null) {
    return {
      valid: false,
      failedClaim: 'exp',
      error_description: 'exp claim must be present',
    };
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (nowSeconds - payload.exp > clockSkewSeconds) {
    return {
      valid: false,
      failedClaim: 'exp',
      error_description: `Client_Assertion has expired (exp: ${payload.exp}, now: ${nowSeconds}, skew: ${clockSkewSeconds}s)`,
    };
  }

  // 5. iat must be present (Requirement 2.13)
  if (payload.iat === undefined || payload.iat === null) {
    return {
      valid: false,
      failedClaim: 'iat',
      error_description: 'iat claim must be present',
    };
  }

  // 6. jti must be present and a non-empty string (Requirement 2.14)
  if (typeof payload.jti !== 'string' || payload.jti.trim() === '') {
    return {
      valid: false,
      failedClaim: 'jti',
      error_description: 'jti claim must be a non-empty string',
    };
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Check whether the `aud` claim contains the given URL.
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
