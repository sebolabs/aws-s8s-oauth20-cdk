/**
 * Auth_Server Lambda handler — orchestrates the OAuth 2.0 token issuance flow.
 *
 * Routes POST /oauth2/token to handleToken; returns 404 for all other paths,
 * and 405 for non-POST on /oauth2/token.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 1.2, 1.7, 2.1–2.15, 3.1–3.6, 4.1–4.7, 5.1–5.7, 9.1, 9.4, 9.5, 9.8, 9.9, 9.10
 */

import * as crypto from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { KMSClient } from '@aws-sdk/client-kms';
import { log } from '../../shared/logger';
import { decodeJwtHeader, decodeJwtPayload, buildJwtHeader, buildJwtPayload } from '../../shared/jwt';
import { validateTokenRequest, ValidationFailure } from './validation';
import {
  lookupClient,
  fetchJwks,
  findJwkByKid,
  ClientNotFoundError,
  ClientInactiveError,
  DynamoError as JwksDynamoError,
  JwksFetchError,
} from './jwks';
import { validateAssertionClaims, AssertionValidationFailure } from './assertion-validation';
import { validateScope } from './scope';
import { storeJti, DynamoError as JtiDynamoError } from './jti-store';
import { buildAccessTokenPayload, signWithKms, KmsSignError } from './token';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT = 'AUTH_SERVER' as const;

// ---------------------------------------------------------------------------
// AWS SDK clients (module-level for Lambda warm-start reuse)
// ---------------------------------------------------------------------------

const dynamoRaw = new DynamoDBClient({});
const dynamoClient = DynamoDBDocumentClient.from(dynamoRaw);
const kmsClient = new KMSClient({});

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handler(event: any): Promise<any> {
  const correlationId: string = event?.requestContext?.requestId ?? 'unknown';

  try {
    const path = event.path || event.resource || '';
    const method = (event.httpMethod || '').toUpperCase();

    if (path === '/oauth2/token') {
      if (method !== 'POST') {
        return buildErrorResponse(405, 'method_not_allowed', 'Only POST is accepted on /oauth2/token');
      }
      return await handleToken(event, correlationId);
    }

    return buildErrorResponse(404, 'not_found', 'The requested resource was not found');
  } catch (err: unknown) {
    log('ERROR', 'UNHANDLED_EXCEPTION', COMPONENT, correlationId, {
      exception_type: err instanceof Error ? err.constructor.name : typeof err,
      message: err instanceof Error ? err.message : String(err),
      stack_trace: err instanceof Error ? err.stack : undefined,
    });
    return buildErrorResponse(500, 'server_error', 'An unexpected error occurred');
  }
}

// ---------------------------------------------------------------------------
// Token Issuance Flow
// ---------------------------------------------------------------------------

async function handleToken(event: any, correlationId: string): Promise<any> {
  // --- Environment variables ---
  const kmsKeyId = process.env.KMS_KEY_ID!;
  const jtiTableName = process.env.JTI_TABLE_NAME!;
  const tokenEndpointUrl = process.env.TOKEN_ENDPOINT_URL!;
  const appointmentsEndpointUrl = process.env.APPOINTMENTS_ENDPOINT_URL!;
  const clockSkewSeconds = parseInt(process.env.CLOCK_SKEW_TOLERANCE_SECONDS || '10', 10);
  const jwksCacheTtlMs = parseInt(process.env.JWKS_CACHE_TTL_SECONDS || '3600', 10) * 1000;

  // --- Step 1: Parse & validate form body ---
  const contentType = extractHeader(event.headers, 'content-type');
  const body = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64').toString('utf8')
    : event.body || '';
  const params = parseFormBody(body);

  const validation = validateTokenRequest(params, contentType);
  if (!validation.valid) {
    const failure = validation as ValidationFailure;
    return buildErrorResponse(failure.statusCode, failure.error, failure.error_description);
  }

  const clientId = params.client_id!;
  const clientAssertion = params.client_assertion!;
  const requestedScope = params.scope;

  // Log TOKEN_REQUEST_RECEIVED
  log('INFO', 'TOKEN_REQUEST_RECEIVED', COMPONENT, correlationId, { client_id: clientId });

  // --- Step 2: Look up client in Client_Registry ---
  let clientRecord;
  try {
    clientRecord = await lookupClient(clientId, dynamoClient);
  } catch (err: unknown) {
    if (err instanceof ClientNotFoundError) {
      log('WARN', 'CLIENT_NOT_FOUND', COMPONENT, correlationId, {
        client_id: clientId,
        error: 'invalid_client',
        error_description: err.message,
      });
      return buildErrorResponse(401, 'invalid_client', err.message);
    }
    if (err instanceof ClientInactiveError) {
      log('WARN', 'CLIENT_INACTIVE', COMPONENT, correlationId, {
        client_id: clientId,
        error: 'invalid_client',
        error_description: err.message,
      });
      return buildErrorResponse(401, 'invalid_client', err.message);
    }
    if (err instanceof JwksDynamoError) {
      return buildErrorResponse(500, 'server_error', 'Internal server error during client lookup');
    }
    throw err;
  }

  log('INFO', 'CLIENT_LOOKUP_SUCCEEDED', COMPONENT, correlationId, { client_id: clientId });

  // --- Step 3: Decode Client_Assertion JWT header to get kid ---
  let jwtHeader;
  try {
    jwtHeader = decodeJwtHeader(clientAssertion);
  } catch {
    log('WARN', 'ASSERTION_SIGNATURE_INVALID', COMPONENT, correlationId, {
      client_id: clientId,
      error: 'invalid_client',
      error_description: 'Malformed Client_Assertion JWT',
    });
    return buildErrorResponse(401, 'invalid_client', 'Malformed Client_Assertion JWT');
  }

  const kid = jwtHeader.kid;
  if (!kid) {
    log('WARN', 'ASSERTION_SIGNATURE_INVALID', COMPONENT, correlationId, {
      client_id: clientId,
      error: 'invalid_client',
      error_description: 'kid claim absent from Client_Assertion JWT header',
    });
    return buildErrorResponse(401, 'invalid_client', 'kid claim absent from Client_Assertion JWT header');
  }

  // --- Step 4: Fetch JWKS from client's jwks_uri ---
  let jwks;
  try {
    jwks = await fetchJwks(clientRecord.jwks_uri, jwksCacheTtlMs);
  } catch (err: unknown) {
    const desc = err instanceof JwksFetchError ? err.message : 'Failed to fetch JWKS';
    log('ERROR', 'JWKS_FETCH_FAILED', COMPONENT, correlationId, {
      client_id: clientId,
      jwks_uri: clientRecord.jwks_uri,
      error: 'invalid_client',
      error_description: desc,
    });
    return buildErrorResponse(401, 'invalid_client', desc);
  }

  log('INFO', 'JWKS_FETCHED', COMPONENT, correlationId, {
    client_id: clientId,
    jwks_uri: clientRecord.jwks_uri,
    from_cache: false, // fetchJwks handles caching internally; we log conservatively
  });

  // --- Step 5: Find JWK by kid ---
  const jwk = findJwkByKid(jwks, kid);
  if (!jwk) {
    log('WARN', 'ASSERTION_SIGNATURE_INVALID', COMPONENT, correlationId, {
      client_id: clientId,
      error: 'invalid_client',
      error_description: `kid "${kid}" not found in JWKS`,
    });
    return buildErrorResponse(401, 'invalid_client', `kid "${kid}" not found in JWKS`);
  }

  // --- Step 6: Verify Client_Assertion signature (RS256) ---
  const signatureValid = verifyRs256Signature(clientAssertion, jwk);
  if (!signatureValid) {
    log('WARN', 'ASSERTION_SIGNATURE_INVALID', COMPONENT, correlationId, {
      client_id: clientId,
      error: 'invalid_client',
      error_description: 'Client_Assertion signature verification failed',
    });
    return buildErrorResponse(401, 'invalid_client', 'Client_Assertion signature verification failed');
  }

  // Decode payload for claims validation
  const assertionPayload = decodeJwtPayload(clientAssertion);

  log('INFO', 'ASSERTION_SIGNATURE_VERIFIED', COMPONENT, correlationId, {
    client_id: clientId,
    jti: assertionPayload.jti,
  });

  // --- Step 7: Validate assertion claims ---
  const claimsResult = validateAssertionClaims(assertionPayload, clientId, tokenEndpointUrl, clockSkewSeconds);
  if (!claimsResult.valid) {
    const failure = claimsResult as AssertionValidationFailure;
    log('WARN', 'CLAIMS_VALIDATION_FAILED', COMPONENT, correlationId, {
      client_id: clientId,
      failed_claim: failure.failedClaim,
      error: 'invalid_client',
      error_description: failure.error_description,
    });
    return buildErrorResponse(401, 'invalid_client', failure.error_description);
  }

  log('INFO', 'CLAIMS_VALIDATED', COMPONENT, correlationId, {
    client_id: clientId,
    jti: assertionPayload.jti,
  });

  // --- Step 8: Validate scope ---
  const scopeResult = validateScope(requestedScope, clientRecord.allowed_scopes);
  if (!scopeResult.valid) {
    return buildErrorResponse(400, 'invalid_scope', 'Requested scope is not a subset of allowed scopes');
  }

  const grantedScope = scopeResult.grantedScope;

  // --- Step 9: Store JTI (replay detection) ---
  const jti = assertionPayload.jti as string;
  const exp = assertionPayload.exp as number;

  let jtiResult;
  try {
    jtiResult = await storeJti(jti, clientId, exp, dynamoClient, jtiTableName);
  } catch (err: unknown) {
    if (err instanceof JtiDynamoError) {
      return buildErrorResponse(500, 'server_error', 'Internal server error during JTI storage');
    }
    throw err;
  }

  if (!jtiResult.stored) {
    log('WARN', 'JTI_REPLAY_DETECTED', COMPONENT, correlationId, {
      client_id: clientId,
      jti,
      error: 'invalid_client',
      error_description: 'JTI has already been used (replay detected)',
    });
    return buildErrorResponse(401, 'invalid_client', 'JTI has already been used (replay detected)');
  }

  log('INFO', 'JTI_STORED', COMPONENT, correlationId, { jti, ttl: exp });

  // --- Step 10: Build and sign Access_Token via KMS ---
  const accessTokenClaims = buildAccessTokenPayload(clientId, tokenEndpointUrl, appointmentsEndpointUrl, grantedScope);
  const headerB64 = buildJwtHeader('RS256', kmsKeyId);
  const payloadB64 = buildJwtPayload(accessTokenClaims as unknown as Record<string, unknown>);

  let accessToken: string;
  try {
    accessToken = await signWithKms(headerB64, payloadB64, kmsKeyId, kmsClient);
  } catch (err: unknown) {
    const desc = err instanceof KmsSignError ? err.message : 'Failed to sign Access_Token';
    log('ERROR', 'KMS_SIGN_FAILED', COMPONENT, correlationId, {
      client_id: clientId,
      error: 'server_error',
      error_description: desc,
    });
    return buildErrorResponse(500, 'server_error', desc);
  }

  // --- Step 11: Return 200 with token response ---
  log('INFO', 'ACCESS_TOKEN_ISSUED', COMPONENT, correlationId, {
    client_id: clientId,
    jti: accessTokenClaims.jti,
    exp: accessTokenClaims.exp,
  });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 180,
    }),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse a URL-encoded form body into a key-value object.
 */
function parseFormBody(body: string): Record<string, string | undefined> {
  const params: Record<string, string | undefined> = {};
  if (!body) return params;

  const pairs = body.split('&');
  for (const pair of pairs) {
    const [key, ...valueParts] = pair.split('=');
    const decodedKey = decodeURIComponent(key || '');
    const decodedValue = decodeURIComponent(valueParts.join('=') || '');
    if (decodedKey) {
      params[decodedKey] = decodedValue;
    }
  }
  return params;
}

/**
 * Extract a header value case-insensitively.
 */
function extractHeader(headers: Record<string, string> | null | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const lowerName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName) {
      return value;
    }
  }
  return undefined;
}

/**
 * Verify an RS256 JWT signature using a JWK (RSA public key).
 */
function verifyRs256Signature(token: string, jwk: { n?: string; e?: string; [key: string]: unknown }): boolean {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const [headerB64, payloadB64, signatureB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;

    // Convert base64url signature to Buffer
    const signatureBuffer = Buffer.from(
      signatureB64.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (signatureB64.length % 4)) % 4),
      'base64',
    );

    // Build RSA public key from JWK components
    if (!jwk.n || !jwk.e) return false;

    const keyObject = crypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: jwk.n,
        e: jwk.e,
      },
      format: 'jwk',
    });

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signingInput);
    return verifier.verify(keyObject, signatureBuffer);
  } catch {
    return false;
  }
}

/**
 * Build a standard OAuth 2.0 error response.
 */
function buildErrorResponse(statusCode: number, error: string, errorDescription: string): any {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error, error_description: errorDescription }),
  };
}
