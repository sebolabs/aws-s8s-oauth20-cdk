/**
 * Lambda_Authorizer handler — REQUEST-type API Gateway authorizer.
 *
 * Validates Access_Token JWT from the Authorization header:
 * 1. Extracts Bearer token
 * 2. Validates JWT structure (3 dot-separated base64url segments)
 * 3. Retrieves KMS public key (cached)
 * 4. Verifies RS256 signature
 * 5. Validates claims (exp, scope, iss, aud)
 * 6. Returns IAM allow/deny policy
 *
 * Feature: oauth2-apig-poc
 * Requirements: 6.1–6.10, 9.1, 9.6, 9.7, 9.9
 */

import * as crypto from 'crypto';
import { KMSClient } from '@aws-sdk/client-kms';
import { log } from '../../shared/logger';
import { decodeJwtHeader, decodeJwtPayload } from '../../shared/jwt';
import { getPublicKey, KmsKeyFetchError } from './kms-key-cache';
import { validateAccessTokenClaims } from './validation';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT = 'LAMBDA_AUTHORIZER' as const;

// ---------------------------------------------------------------------------
// AWS SDK clients (module-level for Lambda warm-start reuse)
// ---------------------------------------------------------------------------

const kmsClient = new KMSClient({});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface IAMPolicyDocument {
  principalId: string;
  policyDocument: {
    Version: string;
    Statement: Array<{
      Effect: 'Allow' | 'Deny';
      Action: string;
      Resource: string;
    }>;
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handler(event: any): Promise<IAMPolicyDocument> {
  const correlationId: string = event?.requestContext?.requestId ?? 'unknown';
  const resourcePath: string = event?.resource || event?.path || '';

  try {
    log('INFO', 'AUTHORIZER_INVOKED', COMPONENT, correlationId, {
      resource_path: resourcePath,
    });

    // --- Environment variables ---
    const kmsKeyId = process.env.KMS_KEY_ID!;
    const tokenEndpointUrl = process.env.TOKEN_ENDPOINT_URL!;
    const appointmentsEndpointUrl = process.env.APPOINTMENTS_ENDPOINT_URL!;
    const clockSkewSeconds = parseInt(process.env.CLOCK_SKEW_TOLERANCE_SECONDS || '10', 10);
    const methodArn: string = event.methodArn || '*';

    // --- Step 1: Extract Authorization header and parse Bearer token ---
    const authHeader = extractHeader(event.headers, 'authorization');
    if (!authHeader) {
      log('WARN', 'TOKEN_MISSING_OR_MALFORMED', COMPONENT, correlationId, {
        reason: 'Authorization header is absent',
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason: 'Authorization header is absent',
      });
      return buildDenyPolicy(methodArn);
    }

    const token = parseBearerToken(authHeader);
    if (!token) {
      log('WARN', 'TOKEN_MISSING_OR_MALFORMED', COMPONENT, correlationId, {
        reason: 'Authorization header does not contain a valid Bearer token',
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason: 'Authorization header does not contain a valid Bearer token',
      });
      return buildDenyPolicy(methodArn);
    }

    // --- Step 2: Validate JWT structure (3 non-empty base64url segments) ---
    if (!isValidJwtStructure(token)) {
      log('WARN', 'TOKEN_MISSING_OR_MALFORMED', COMPONENT, correlationId, {
        reason: 'Token does not have valid JWT structure (3 non-empty base64url segments)',
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason: 'Token does not have valid JWT structure',
      });
      return buildDenyPolicy(methodArn);
    }

    // --- Step 3: Retrieve KMS public key (with cache) ---
    let publicKey: Buffer;
    try {
      publicKey = await getPublicKey(kmsKeyId, kmsClient);
    } catch (err: unknown) {
      const reason = err instanceof KmsKeyFetchError
        ? `KMS key fetch failed: ${err.message}`
        : 'Failed to retrieve KMS public key';
      log('WARN', 'TOKEN_SIGNATURE_INVALID', COMPONENT, correlationId, {
        reason,
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason,
      });
      return buildDenyPolicy(methodArn);
    }

    // --- Step 4: Verify RS256 signature ---
    const signatureValid = verifyRs256Signature(token, publicKey);
    if (!signatureValid) {
      log('WARN', 'TOKEN_SIGNATURE_INVALID', COMPONENT, correlationId, {
        reason: 'RS256 signature verification failed',
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason: 'RS256 signature verification failed',
      });
      return buildDenyPolicy(methodArn);
    }

    // Decode payload for claims validation and logging
    const payload = decodeJwtPayload(token);
    const sub = payload.sub || 'unknown';
    const jti = payload.jti || 'unknown';

    log('INFO', 'TOKEN_SIGNATURE_VERIFIED', COMPONENT, correlationId, {
      sub,
      jti,
    });

    // --- Step 5: Validate claims ---
    const claimsResult = validateAccessTokenClaims(
      payload,
      tokenEndpointUrl,
      appointmentsEndpointUrl,
      clockSkewSeconds,
    );

    if (!claimsResult.valid) {
      const failedClaim = claimsResult.failedClaim;
      const reason = claimsResult.reason;
      log('WARN', 'CLAIMS_VALIDATION_FAILED', COMPONENT, correlationId, {
        failed_claim: failedClaim,
        reason,
      });
      log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
        reason: `Claims validation failed: ${failedClaim}`,
      });
      return buildDenyPolicy(methodArn);
    }

    log('INFO', 'CLAIMS_VALIDATED', COMPONENT, correlationId, {
      sub,
      scope: payload.scope,
    });

    // --- Step 6: Return IAM allow policy ---
    log('INFO', 'ACCESS_GRANTED', COMPONENT, correlationId, {
      sub,
    });

    return buildAllowPolicy(sub, methodArn);
  } catch (err: unknown) {
    log('ERROR', 'UNHANDLED_EXCEPTION', COMPONENT, correlationId, {
      exception_type: err instanceof Error ? err.constructor.name : typeof err,
      message: err instanceof Error ? err.message : String(err),
      stack_trace: err instanceof Error ? err.stack : undefined,
    });
    const methodArn: string = event?.methodArn || '*';
    log('WARN', 'ACCESS_DENIED', COMPONENT, correlationId, {
      reason: 'Unhandled exception',
    });
    return buildDenyPolicy(methodArn);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
 * Parse a Bearer token from the Authorization header value.
 * Returns the token string if valid "Bearer <token>" format, or null otherwise.
 */
function parseBearerToken(authHeader: string): string | null {
  const parts = authHeader.split(' ');
  if (parts.length !== 2) return null;
  if (parts[0].toLowerCase() !== 'bearer') return null;
  const token = parts[1];
  if (!token || token.length === 0) return null;
  return token;
}

/**
 * Validate JWT structure: exactly 3 dot-separated segments, each being non-empty base64url strings.
 */
function isValidJwtStructure(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const base64urlPattern = /^[A-Za-z0-9_-]+$/;
  for (const part of parts) {
    if (!part || part.length === 0) return false;
    if (!base64urlPattern.test(part)) return false;
  }

  return true;
}

/**
 * Verify an RS256 JWT signature using a DER-encoded public key from KMS.
 */
function verifyRs256Signature(token: string, publicKeyDer: Buffer): boolean {
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

    // Create public key object from DER-encoded buffer
    const keyObject = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki',
    });

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signingInput);
    return verifier.verify(keyObject, signatureBuffer);
  } catch {
    return false;
  }
}

/**
 * Build an IAM allow policy.
 */
function buildAllowPolicy(principalId: string, resource: string): IAMPolicyDocument {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow',
        Action: 'execute-api:Invoke',
        Resource: resource,
      }],
    },
  };
}

/**
 * Build an IAM deny policy.
 */
function buildDenyPolicy(resource: string): IAMPolicyDocument {
  return {
    principalId: 'anonymous',
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Deny',
        Action: 'execute-api:Invoke',
        Resource: resource,
      }],
    },
  };
}
