/**
 * KMS public key cache module for the Lambda_Authorizer.
 *
 * Provides:
 * - getPublicKey: retrieves the KMS public key (DER-encoded) with 60-minute in-memory cache
 *
 * The cache survives Lambda warm invocations. TTL is configurable via
 * the `KMS_KEY_CACHE_TTL_SECONDS` environment variable (default 3600).
 *
 * Feature: oauth2-apig-poc
 * Requirements: 6.3, 6.4
 */

import { KMSClient, GetPublicKeyCommand } from '@aws-sdk/client-kms';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KeyCacheEntry {
  publicKey: Buffer;
  fetchedAt: number;
}

export interface KeyCache {
  get(keyId: string): KeyCacheEntry | undefined;
  set(keyId: string, entry: KeyCacheEntry): void;
}

// ---------------------------------------------------------------------------
// Typed Errors
// ---------------------------------------------------------------------------

export class KmsKeyFetchError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'KmsKeyFetchError';
  }
}

// ---------------------------------------------------------------------------
// Module-level cache (survives Lambda warm invocations)
// ---------------------------------------------------------------------------

const moduleCache: Map<string, KeyCacheEntry> = new Map();

const defaultCache: KeyCache = {
  get: (keyId: string) => moduleCache.get(keyId),
  set: (keyId: string, entry: KeyCacheEntry) => { moduleCache.set(keyId, entry); },
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Retrieve the KMS public key material (DER-encoded), using an in-memory cache.
 *
 * @param kmsKeyId - The KMS key ID to retrieve the public key for
 * @param kmsClient - An instance of KMSClient
 * @param cache - Optional cache implementation (defaults to module-level Map cache)
 * @returns Buffer containing the DER-encoded public key material
 * @throws {KmsKeyFetchError} if the KMS GetPublicKey call fails
 */
export async function getPublicKey(
  kmsKeyId: string,
  kmsClient: KMSClient,
  cache: KeyCache = defaultCache,
): Promise<Buffer> {
  const cacheTtlSeconds = parseInt(
    process.env.KMS_KEY_CACHE_TTL_SECONDS || '3600',
    10,
  );
  const cacheTtlMs = cacheTtlSeconds * 1000;

  const cached = cache.get(kmsKeyId);
  const now = Date.now();

  if (cached && now - cached.fetchedAt < cacheTtlMs) {
    return cached.publicKey;
  }

  let publicKeyBytes: Uint8Array;
  try {
    const response = await kmsClient.send(
      new GetPublicKeyCommand({ KeyId: kmsKeyId }),
    );

    if (!response.PublicKey) {
      throw new Error('KMS GetPublicKey response did not contain PublicKey material');
    }

    publicKeyBytes = response.PublicKey;
  } catch (err: unknown) {
    if (err instanceof KmsKeyFetchError) {
      throw err;
    }
    throw new KmsKeyFetchError(
      `Failed to retrieve public key from KMS for key "${kmsKeyId}"`,
      err,
    );
  }

  const publicKey = Buffer.from(publicKeyBytes);

  cache.set(kmsKeyId, { publicKey, fetchedAt: now });

  return publicKey;
}

/**
 * Clear the module-level key cache. Useful for testing.
 */
export function clearKeyCache(): void {
  moduleCache.clear();
}
