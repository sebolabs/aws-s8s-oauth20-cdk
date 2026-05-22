/**
 * Client_Registry lookup and JWKS fetch/cache module for the Auth_Server.
 *
 * Provides:
 * - lookupClient: retrieves client record from Client_Registry DynamoDB table
 * - fetchJwks: fetches JWKS from a URI with 60-minute in-memory cache
 * - findJwkByKid: finds a JWK by kid in a JWKS key set
 *
 * Feature: oauth2-apig-poc
 * Requirements: 2.3, 2.4, 2.5, 2.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.7
 */

import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ClientRecord {
  client_id: string;
  jwks_uri: string;
  allowed_scopes: string;
  status: string;
}

export interface Jwk {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

export interface Jwks {
  keys: Jwk[];
}

export interface JwksCacheEntry {
  jwks: Jwks;
  fetchedAt: number;
}

// ---------------------------------------------------------------------------
// Typed Errors
// ---------------------------------------------------------------------------

export class ClientNotFoundError extends Error {
  constructor(clientId: string) {
    super(`Client not found: ${clientId}`);
    this.name = 'ClientNotFoundError';
  }
}

export class ClientInactiveError extends Error {
  constructor(clientId: string) {
    super(`Client is inactive: ${clientId}`);
    this.name = 'ClientInactiveError';
  }
}

export class DynamoError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'DynamoError';
  }
}

export class JwksFetchError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'JwksFetchError';
  }
}

// ---------------------------------------------------------------------------
// Module-level JWKS cache (survives Lambda warm invocations)
// ---------------------------------------------------------------------------

const jwksCache: Map<string, JwksCacheEntry> = new Map();

const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000; // 60 minutes

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up a client in the Client_Registry DynamoDB table.
 *
 * @param clientId - The client_id to look up
 * @param dynamoClient - DynamoDBDocumentClient instance
 * @returns The client record
 * @throws {ClientNotFoundError} if the client_id is not found
 * @throws {ClientInactiveError} if the client status is not "active"
 * @throws {DynamoError} on DynamoDB infrastructure errors
 */
export async function lookupClient(
  clientId: string,
  dynamoClient: DynamoDBDocumentClient,
): Promise<ClientRecord> {
  const tableName = process.env.CLIENT_REGISTRY_TABLE_NAME;
  if (!tableName) {
    throw new DynamoError('CLIENT_REGISTRY_TABLE_NAME environment variable is not set');
  }

  let result;
  try {
    result = await dynamoClient.send(
      new GetCommand({
        TableName: tableName,
        Key: { client_id: clientId },
      }),
    );
  } catch (err: unknown) {
    throw new DynamoError(
      `Failed to query Client_Registry for client_id "${clientId}"`,
      err,
    );
  }

  if (!result.Item) {
    throw new ClientNotFoundError(clientId);
  }

  const record = result.Item as ClientRecord;

  if (record.status !== 'active') {
    throw new ClientInactiveError(clientId);
  }

  return record;
}

/**
 * Fetch JWKS from a URI with 60-minute in-memory module-level cache.
 *
 * @param jwksUri - The URI to fetch the JWKS from
 * @param cacheTtlMs - Cache TTL in milliseconds (defaults to 60 minutes)
 * @returns Parsed JWKS object
 * @throws {JwksFetchError} if the fetch fails or the response is not valid JWKS
 */
export async function fetchJwks(
  jwksUri: string,
  cacheTtlMs: number = DEFAULT_CACHE_TTL_MS,
): Promise<Jwks> {
  const cached = jwksCache.get(jwksUri);
  const now = Date.now();

  if (cached && now - cached.fetchedAt < cacheTtlMs) {
    return cached.jwks;
  }

  let response: Response;
  try {
    response = await fetch(jwksUri);
  } catch (err: unknown) {
    throw new JwksFetchError(`Failed to fetch JWKS from "${jwksUri}"`, err);
  }

  if (!response.ok) {
    throw new JwksFetchError(
      `JWKS fetch from "${jwksUri}" returned HTTP ${response.status}`,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch (err: unknown) {
    throw new JwksFetchError(
      `JWKS response from "${jwksUri}" is not valid JSON`,
      err,
    );
  }

  if (typeof body !== 'object' || body === null || !Array.isArray((body as Jwks).keys)) {
    throw new JwksFetchError(
      `JWKS response from "${jwksUri}" does not contain a valid "keys" array`,
    );
  }

  const jwks = body as Jwks;

  // Update cache
  jwksCache.set(jwksUri, { jwks, fetchedAt: now });

  return jwks;
}

/**
 * Find a JWK by kid in a JWKS key set.
 *
 * @param jwks - The JWKS object containing the keys array
 * @param kid - The key ID to search for
 * @returns The matching JWK, or null if not found
 */
export function findJwkByKid(jwks: Jwks, kid: string): Jwk | null {
  const match = jwks.keys.find((key) => key.kid === kid);
  return match ?? null;
}

/**
 * Clear the JWKS cache. Useful for testing.
 */
export function clearJwksCache(): void {
  jwksCache.clear();
}
