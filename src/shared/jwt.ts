/**
 * Shared JWT utility — pure functions only, no AWS SDK calls.
 *
 * Provides base64url encode/decode helpers and JWT assembly/disassembly
 * used by Auth_Server, Lambda_Authorizer, and PCA_Lambda.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 2.1, 4.2, 12.3
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  jti?: string;
  scope?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Decode a base64url-encoded string to a UTF-8 string.
 * Handles missing padding and the url-safe alphabet (- and _).
 */
function base64urlDecode(input: string): string {
  // Convert base64url → base64
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

/**
 * Encode a UTF-8 string (or Buffer) to base64url without padding.
 */
function base64urlEncode(input: string | Buffer): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Decode the header segment of a JWT without verifying the signature.
 *
 * @throws {Error} if the token is malformed (wrong number of segments, invalid base64url, or non-JSON header)
 */
export function decodeJwtHeader(token: string): JwtHeader {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Malformed JWT: expected 3 segments, got ${parts.length}`);
  }

  const [headerB64] = parts;
  let decoded: string;
  try {
    decoded = base64urlDecode(headerB64);
  } catch {
    throw new Error('Malformed JWT: header segment is not valid base64url');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    throw new Error('Malformed JWT: header segment is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Malformed JWT: header must be a JSON object');
  }

  return parsed as JwtHeader;
}

/**
 * Decode the payload segment of a JWT without verifying the signature.
 *
 * @throws {Error} if the token is malformed
 */
export function decodeJwtPayload(token: string): JwtPayload {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Malformed JWT: expected 3 segments, got ${parts.length}`);
  }

  const payloadB64 = parts[1];
  let decoded: string;
  try {
    decoded = base64urlDecode(payloadB64);
  } catch {
    throw new Error('Malformed JWT: payload segment is not valid base64url');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    throw new Error('Malformed JWT: payload segment is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Malformed JWT: payload must be a JSON object');
  }

  return parsed as JwtPayload;
}

/**
 * Build a base64url-encoded JWT header segment.
 *
 * @param alg - Signing algorithm (e.g. "RS256")
 * @param kid - Key ID
 * @returns base64url-encoded header string (no padding)
 */
export function buildJwtHeader(alg: string, kid: string): string {
  const header: JwtHeader = { alg, kid, typ: 'JWT' };
  return base64urlEncode(JSON.stringify(header));
}

/**
 * Build a base64url-encoded JWT payload segment.
 *
 * @param claims - Arbitrary claims object
 * @returns base64url-encoded payload string (no padding)
 */
export function buildJwtPayload(claims: Record<string, unknown>): string {
  return base64urlEncode(JSON.stringify(claims));
}

/**
 * Assemble a complete JWT string from pre-encoded header, payload, and raw signature bytes.
 *
 * @param header    - base64url-encoded header (from buildJwtHeader)
 * @param payload   - base64url-encoded payload (from buildJwtPayload)
 * @param signature - Raw signature bytes (e.g. from KMS sign response)
 * @returns Dot-separated JWT string: `<header>.<payload>.<signature>`
 */
export function assembleJwt(header: string, payload: string, signature: Buffer): string {
  const sigB64url = base64urlEncode(signature);
  return `${header}.${payload}.${sigB64url}`;
}
