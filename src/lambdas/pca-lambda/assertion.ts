/**
 * PCA Client_Assertion construction and KMS signing.
 *
 * Provides:
 * - buildAssertionPayload: constructs the Client_Assertion JWT claims object
 * - signAssertionWithKms: signs the JWT using AWS KMS and returns the assembled token
 *
 * Feature: oauth2-apig-poc
 * Requirements: 12.2, 12.3
 */

import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { buildJwtHeader, buildJwtPayload, assembleJwt } from '../../shared/jwt';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AssertionClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
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
 * Build the Client_Assertion JWT payload claims.
 *
 * @param pcaClientId - The PCA client_id (becomes both `iss` and `sub`)
 * @param tokenEndpointUrl - The Token_Endpoint URL (becomes `aud`)
 * @param nowSeconds - Current time in seconds since epoch
 * @returns Claims object ready for JWT payload encoding
 */
export function buildAssertionPayload(
  pcaClientId: string,
  tokenEndpointUrl: string,
  nowSeconds: number,
): AssertionClaims {
  return {
    iss: pcaClientId,
    sub: pcaClientId,
    aud: tokenEndpointUrl,
    exp: nowSeconds + 180,
    iat: nowSeconds,
    jti: crypto.randomUUID(),
  };
}

/**
 * Sign a Client_Assertion JWT using AWS KMS with RSASSA_PKCS1_V1_5_SHA_256
 * and return the assembled token.
 *
 * @param payload - The assertion claims object
 * @param pcaKmsKeyId - The PCA KMS key ID to sign with
 * @param kmsClient - An instance of KMSClient
 * @returns The assembled JWT string (header.payload.signature)
 * @throws {KmsSignError} if the KMS sign operation fails
 */
export async function signAssertionWithKms(
  payload: AssertionClaims,
  pcaKmsKeyId: string,
  kmsClient: KMSClient,
): Promise<string> {
  const headerB64 = buildJwtHeader('RS256', pcaKmsKeyId);
  const payloadB64 = buildJwtPayload(payload as unknown as Record<string, unknown>);

  const message = `${headerB64}.${payloadB64}`;
  const messageBytes = Buffer.from(message, 'utf8');

  let signature: Uint8Array;
  try {
    const response = await kmsClient.send(
      new SignCommand({
        KeyId: pcaKmsKeyId,
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
      `Failed to sign Client_Assertion with KMS key "${pcaKmsKeyId}"`,
      err,
    );
  }

  return assembleJwt(headerB64, payloadB64, Buffer.from(signature));
}
