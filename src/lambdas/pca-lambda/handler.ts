/**
 * PCA_Lambda handler — orchestrates the PCA Emulator flows.
 *
 * Routes:
 * - POST /token         → handleToken (OAuth token request)
 * - POST /appointments  → handleAppointments (business request)
 * - GET /.well-known/jwks.json → handleJwks (public key endpoint)
 * - All other paths     → 404
 *
 * Feature: oauth2-apig-poc
 * Requirements: 11.1, 12.1–12.6, 13.1–13.5, 9.1, 9.2, 9.3, 9.9
 */

import { KMSClient } from '@aws-sdk/client-kms';
import { log } from '../../shared/logger';
import { buildAssertionPayload, signAssertionWithKms } from './assertion';
import { handleAppointments } from './appointments';
import { buildJwksResponse } from './jwks';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COMPONENT = 'PCA_LAMBDA' as const;

// ---------------------------------------------------------------------------
// AWS SDK clients (module-level for Lambda warm-start reuse)
// ---------------------------------------------------------------------------

const kmsClient = new KMSClient({});

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handler(event: any): Promise<any> {
  const correlationId: string = event?.requestContext?.requestId ?? 'unknown';

  try {
    const path = event.path || event.resource || '';
    const method = (event.httpMethod || '').toUpperCase();

    if (path === '/token' && method === 'POST') {
      return await handleToken(event, correlationId);
    }

    if (path === '/appointments' && method === 'POST') {
      return await handleAppointmentsRoute(event, correlationId);
    }

    if (path === '/.well-known/jwks.json' && method === 'GET') {
      return await handleJwks(correlationId);
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
// Token Flow (POST /token)
// ---------------------------------------------------------------------------

async function handleToken(_event: any, correlationId: string): Promise<any> {
  const pcaKmsKeyId = process.env.PCA_KMS_KEY_ID!;
  const pcaClientId = process.env.PCA_CLIENT_ID!;
  const tokenEndpointUrl = process.env.TOKEN_ENDPOINT_URL!;

  // Step 1: Build assertion payload
  const nowSeconds = Math.floor(Date.now() / 1000);
  const payload = buildAssertionPayload(pcaClientId, tokenEndpointUrl, nowSeconds);

  // Step 2: Sign with KMS
  const jwt = await signAssertionWithKms(payload, pcaKmsKeyId, kmsClient);

  // Step 3: Log JWT_ASSERTION_CREATED
  log('INFO', 'JWT_ASSERTION_CREATED', COMPONENT, correlationId, {
    client_id: pcaClientId,
    jti: payload.jti,
    exp: payload.exp,
  });

  // Step 4: POST to Token_Endpoint
  const formBody = [
    'grant_type=client_credentials',
    'client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer',
    `client_assertion=${jwt}`,
    `client_id=${pcaClientId}`,
  ].join('&');

  log('INFO', 'TOKEN_REQUEST_SENT', COMPONENT, correlationId, {
    token_endpoint_url: tokenEndpointUrl,
  });

  const response = await fetch(tokenEndpointUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formBody,
  });

  const responseBody = await response.text();

  // Step 5: Handle response
  if (response.status === 200) {
    let parsed: any;
    try {
      parsed = JSON.parse(responseBody);
    } catch {
      parsed = {};
    }

    log('INFO', 'TOKEN_REQUEST_SUCCEEDED', COMPONENT, correlationId, {
      expires_in: parsed.expires_in,
    });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: responseBody,
    };
  }

  // Non-200: log failure and return 502
  let errorParsed: any;
  try {
    errorParsed = JSON.parse(responseBody);
  } catch {
    errorParsed = {};
  }

  log('ERROR', 'TOKEN_REQUEST_FAILED', COMPONENT, correlationId, {
    status_code: response.status,
    error: errorParsed.error,
    error_description: errorParsed.error_description,
  });

  return {
    statusCode: 502,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      error: errorParsed.error || 'upstream_error',
      error_description: errorParsed.error_description || 'Token endpoint returned an error',
    }),
  };
}

// ---------------------------------------------------------------------------
// Appointments Flow (POST /appointments)
// ---------------------------------------------------------------------------

async function handleAppointmentsRoute(event: any, correlationId: string): Promise<any> {
  const appointmentsEndpointUrl = process.env.APPOINTMENTS_ENDPOINT_URL!;

  log('INFO', 'APPOINTMENTS_REQUEST_SENT', COMPONENT, correlationId, {
    appointments_endpoint_url: appointmentsEndpointUrl,
  });

  const result = await handleAppointments(event.body, appointmentsEndpointUrl);

  if (result.statusCode === 200) {
    log('INFO', 'APPOINTMENTS_REQUEST_SUCCEEDED', COMPONENT, correlationId, {
      status_code: result.statusCode,
    });
  } else {
    log('ERROR', 'APPOINTMENTS_REQUEST_FAILED', COMPONENT, correlationId, {
      status_code: result.statusCode,
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// JWKS Flow (GET /.well-known/jwks.json)
// ---------------------------------------------------------------------------

async function handleJwks(correlationId: string): Promise<any> {
  const pcaKmsKeyId = process.env.PCA_KMS_KEY_ID!;

  const jwksResponse = await buildJwksResponse(pcaKmsKeyId, kmsClient, correlationId);

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(jwksResponse),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildErrorResponse(statusCode: number, error: string, errorDescription: string): any {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ error, error_description: errorDescription }),
  };
}
