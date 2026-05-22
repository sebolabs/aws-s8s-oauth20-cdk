/**
 * Access_Token construction and KMS signing for the Auth_Server.
 *
 * Provides:
 * - buildAccessTokenPayload: constructs the Access_Token JWT claims object
 * - signWithKms: signs the JWT using AWS KMS and returns the assembled token
 *
 * Feature: oauth2-apig-poc
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.7
 */

import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { assembleJwt } from '../../shared/jwt';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AccessTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  scope: string;
}

// ---------------------------------------------------------------------------
// Typed Errors
// ---------------------------------------------------------------------------

export class KmsSignError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'KmsSignError';
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build the Access_Token JWT payload claims.
 *
 * @param clientId - The authenticated client_id (becomes `sub`)
 * @param tokenEndpointUrl - The Token_Endpoint URL (becomes `iss`)
 * @param appointmentsEndpointUrl - The Appointments_Endpoint URL (becomes `aud`)
 * @param grantedScope - The granted scope string (e.g. "appointments:read")
 * @param kmsKeyId - The KMS key ID (used only for context; not embedded in payload)
 * @returns Claims object ready for JWT payload encoding
 */
export function buildAccessTokenPayload(
  clientId: string,
  tokenEndpointUrl: string,
  appointmentsEndpointUrl: string,
  grantedScope: string,
): AccessTokenClaims {
  const now = Math.floor(Date.now() / 1000);

  return {
    iss: tokenEndpointUrl,
    sub: clientId,
    aud: appointmentsEndpointUrl,
    exp: now + 180,
    iat: now,
    jti: crypto.randomUUID(),
    scope: grantedScope,
  };
}

/**
 * Sign a JWT using AWS KMS with RSASSA_PKCS1_V1_5_SHA_256 and return the assembled token.
 *
 * @param headerB64 - Base64url-encoded JWT header segment
 * @param payloadB64 - Base64url-encoded JWT payload segment
 * @param kmsKeyId - The KMS key ID to sign with
 * @param kmsClient - An instance of KMSClient
 * @returns The assembled JWT string (header.payload.signature)
 * @throws {KmsSignError} if the KMS sign operation fails
 */
export async function signWithKms(
  headerB64: string,
  payloadB64: string,
  kmsKeyId: string,
  kmsClient: KMSClient,
): Promise<string> {
  const message = `${headerB64}.${payloadB64}`;
  const messageBytes = Buffer.from(message, 'utf8');

  let signature: Uint8Array;
  try {
    const response = await kmsClient.send(
      new SignCommand({
        KeyId: kmsKeyId,
        Message: messageBytes,
        MessageType: 'RAW',
        SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
      }),
    );

    if (!response.Signature) {
      throw new Error('KMS sign response did not contain a Signature');
    }

    signature = response.Signature;
  } catch (err: unknown) {
    if (err instanceof KmsSignError) {
      throw err;
    }
    throw new KmsSignError(
      `Failed to sign Access_Token with KMS key "${kmsKeyId}"`,
      err,
    );
  }

  return assembleJwt(headerB64, payloadB64, Buffer.from(signature));
}
