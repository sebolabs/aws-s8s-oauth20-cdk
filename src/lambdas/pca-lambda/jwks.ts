/**
 * PCA JWKS handler module.
 *
 * Provides:
 * - buildJwksResponse: retrieves the PCA KMS public key, decodes the DER-encoded
 *   SubjectPublicKeyInfo to extract RSA modulus (n) and exponent (e), and returns
 *   a JWKS-formatted response.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 11.1, 11.2, 11.3, 11.4
 */

import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';
import { log } from '../../shared/logger';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JwksResponse {
  keys: JwkEntry[];
}

export interface JwkEntry {
  kty: string;
  use: string;
  alg: string;
  kid: string;
  n: string;
  e: string;
}

// ---------------------------------------------------------------------------
// DER Parsing Helpers
// ---------------------------------------------------------------------------

/**
 * Parse a DER-encoded ASN.1 SubjectPublicKeyInfo structure to extract
 * the RSA modulus (n) and public exponent (e).
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm  AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 *
 * The BIT STRING contains a DER-encoded RSAPublicKey:
 * RSAPublicKey ::= SEQUENCE {
 *   modulus         INTEGER,
 *   publicExponent  INTEGER
 * }
 */
export function parseRsaPublicKeyFromDer(der: Buffer): { n: Buffer; e: Buffer } {
  let offset = 0;

  // Helper: read a DER tag and length, return the content start offset and length
  function readTagAndLength(): { tag: number; length: number; contentOffset: number } {
    const tag = der[offset++];
    let length = der[offset++];

    if (length & 0x80) {
      const numBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | der[offset++];
      }
    }

    return { tag, length, contentOffset: offset };
  }

  // Outer SEQUENCE (SubjectPublicKeyInfo)
  const outerSeq = readTagAndLength();
  if (outerSeq.tag !== 0x30) {
    throw new Error('Expected SEQUENCE tag for SubjectPublicKeyInfo');
  }

  // AlgorithmIdentifier SEQUENCE — skip it
  const algoSeq = readTagAndLength();
  if (algoSeq.tag !== 0x30) {
    throw new Error('Expected SEQUENCE tag for AlgorithmIdentifier');
  }
  offset = algoSeq.contentOffset + algoSeq.length;

  // BIT STRING containing RSAPublicKey
  const bitString = readTagAndLength();
  if (bitString.tag !== 0x03) {
    throw new Error('Expected BIT STRING tag for subjectPublicKey');
  }

  // Skip the "unused bits" byte (should be 0x00 for RSA keys)
  offset++;

  // Inner SEQUENCE (RSAPublicKey)
  const rsaSeq = readTagAndLength();
  if (rsaSeq.tag !== 0x30) {
    throw new Error('Expected SEQUENCE tag for RSAPublicKey');
  }

  // INTEGER: modulus (n)
  const nTag = readTagAndLength();
  if (nTag.tag !== 0x02) {
    throw new Error('Expected INTEGER tag for modulus');
  }
  let nBytes = der.subarray(nTag.contentOffset, nTag.contentOffset + nTag.length);
  // Strip leading zero byte if present (ASN.1 INTEGER padding for positive numbers)
  if (nBytes[0] === 0x00) {
    nBytes = nBytes.subarray(1);
  }
  offset = nTag.contentOffset + nTag.length;

  // INTEGER: public exponent (e)
  const eTag = readTagAndLength();
  if (eTag.tag !== 0x02) {
    throw new Error('Expected INTEGER tag for exponent');
  }
  let eBytes = der.subarray(eTag.contentOffset, eTag.contentOffset + eTag.length);
  // Strip leading zero byte if present
  if (eBytes[0] === 0x00) {
    eBytes = eBytes.subarray(1);
  }

  return { n: Buffer.from(nBytes), e: Buffer.from(eBytes) };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a JWKS response by retrieving the public key from KMS and
 * extracting the RSA components.
 *
 * On KMS failure, returns `{ keys: [] }` and logs the error (does not throw).
 *
 * @param kmsKeyId - The KMS key ID to retrieve the public key for
 * @param kmsClient - An instance of KMSClient
 * @param correlationId - Optional correlation ID for structured logging
 * @returns JWKS response object
 */
export async function buildJwksResponse(
  kmsKeyId: string,
  kmsClient: KMSClient,
  correlationId: string = 'unknown',
): Promise<JwksResponse> {
  let publicKeyDer: Uint8Array;

  try {
    const response = await kmsClient.send(
      new GetPublicKeyCommand({ KeyId: kmsKeyId }),
    );

    if (!response.PublicKey) {
      throw new Error('KMS GetPublicKey response did not contain PublicKey material');
    }

    publicKeyDer = response.PublicKey;
  } catch (err: unknown) {
    log('ERROR', 'KMS_GET_PUBLIC_KEY_FAILED', 'PCA_LAMBDA', correlationId, {
      error: 'kms_error',
      error_description: `Failed to retrieve public key from KMS: ${err instanceof Error ? err.message : String(err)}`,
      kms_key_id: kmsKeyId,
    });
    return { keys: [] };
  }

  try {
    const derBuffer = Buffer.from(publicKeyDer);
    const { n, e } = parseRsaPublicKeyFromDer(derBuffer);

    const jwk: JwkEntry = {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: kmsKeyId,
      n: n.toString('base64url'),
      e: e.toString('base64url'),
    };

    return { keys: [jwk] };
  } catch (err: unknown) {
    log('ERROR', 'DER_PARSE_FAILED', 'PCA_LAMBDA', correlationId, {
      error: 'der_parse_error',
      error_description: `Failed to parse DER-encoded public key: ${err instanceof Error ? err.message : String(err)}`,
      kms_key_id: kmsKeyId,
    });
    return { keys: [] };
  }
}
