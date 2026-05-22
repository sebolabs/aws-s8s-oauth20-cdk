/**
 * Auth_Server request parameter validation — pure module, no AWS SDK calls.
 *
 * Validates incoming token request parameters and Content-Type header
 * before any downstream processing (client lookup, JWT verification, etc.).
 *
 * Feature: oauth2-apig-poc
 * Requirements: 1.3, 1.4, 1.5, 1.6, 1.8
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TokenRequestParams {
  grant_type?: string;
  client_assertion_type?: string;
  client_assertion?: string;
  client_id?: string;
}

export interface ValidationSuccess {
  valid: true;
}

export interface ValidationFailure {
  valid: false;
  statusCode: number;
  error: string;
  error_description: string;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REQUIRED_CONTENT_TYPE = 'application/x-www-form-urlencoded';
const REQUIRED_GRANT_TYPE = 'client_credentials';
const REQUIRED_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const REQUIRED_PARAMS: (keyof TokenRequestParams)[] = [
  'grant_type',
  'client_assertion_type',
  'client_assertion',
  'client_id',
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Validate an incoming token request's Content-Type and form parameters.
 *
 * Checks are applied in the following order:
 * 1. Content-Type must be `application/x-www-form-urlencoded` (→ 415)
 * 2. All four required params must be present and non-blank (→ 400 `invalid_request`)
 * 3. `grant_type` must equal `client_credentials` (→ 400 `invalid_request`)
 * 4. `client_assertion_type` must equal the JWT bearer URN (→ 400 `invalid_request`)
 *
 * @param params      - Parsed form parameters from the request body
 * @param contentType - Value of the Content-Type request header (may be undefined)
 * @returns ValidationSuccess if all checks pass, or ValidationFailure with status code and error details
 */
export function validateTokenRequest(
  params: TokenRequestParams,
  contentType: string | undefined,
): ValidationResult {
  // 1. Content-Type check (Requirement 1.8)
  if (!contentType || !contentType.toLowerCase().startsWith(REQUIRED_CONTENT_TYPE)) {
    return {
      valid: false,
      statusCode: 415,
      error: 'unsupported_media_type',
      error_description: `Content-Type must be ${REQUIRED_CONTENT_TYPE}`,
    };
  }

  // 2. Required parameters presence check (Requirement 1.6)
  for (const param of REQUIRED_PARAMS) {
    const value = params[param];
    if (value === undefined || value === null || value.trim() === '') {
      return {
        valid: false,
        statusCode: 400,
        error: 'invalid_request',
        error_description: `Missing or blank required parameter: ${param}`,
      };
    }
  }

  // 3. grant_type value check (Requirement 1.4)
  if (params.grant_type !== REQUIRED_GRANT_TYPE) {
    return {
      valid: false,
      statusCode: 400,
      error: 'invalid_request',
      error_description: `grant_type must be "${REQUIRED_GRANT_TYPE}"`,
    };
  }

  // 4. client_assertion_type value check (Requirement 1.5)
  if (params.client_assertion_type !== REQUIRED_ASSERTION_TYPE) {
    return {
      valid: false,
      statusCode: 400,
      error: 'invalid_request',
      error_description: `client_assertion_type must be "${REQUIRED_ASSERTION_TYPE}"`,
    };
  }

  return { valid: true };
}
