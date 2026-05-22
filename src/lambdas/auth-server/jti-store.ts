/**
 * JTI Store — DynamoDB-backed replay protection for Client_Assertion JTI claims.
 *
 * Uses a conditional PutItem to atomically detect and reject replayed JTIs.
 * A ConditionalCheckFailedException indicates a duplicate JTI (replay attack).
 *
 * Feature: oauth2-apig-poc
 * Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
 */

import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoreJtiSuccess {
  stored: true;
}

export interface StoreJtiReplay {
  stored: false;
  reason: 'replay';
}

export type StoreJtiResult = StoreJtiSuccess | StoreJtiReplay;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown when a DynamoDB operation fails for reasons other than a conditional
 * check failure (e.g. network error, throttling, permissions).
 */
export class DynamoError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'DynamoError';
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Store a JTI in the JTI_Store table with atomic replay detection.
 *
 * Uses `PutItem` with `ConditionExpression: attribute_not_exists(jti)` so that
 * concurrent requests with the same JTI result in exactly one success.
 *
 * @param jti         - The JWT ID claim value to store
 * @param clientId    - The client_id associated with this assertion
 * @param ttl         - Unix epoch seconds at which DynamoDB should expire the item (equals `exp` of the Client_Assertion)
 * @param dynamoClient - A DynamoDBDocumentClient instance
 * @param tableName   - The name of the JTI_Store DynamoDB table
 *
 * @returns `{ stored: true }` on success, `{ stored: false, reason: 'replay' }` on duplicate JTI
 * @throws {DynamoError} on infrastructure/IO errors (not conditional check failures)
 */
export async function storeJti(
  jti: string,
  clientId: string,
  ttl: number,
  dynamoClient: DynamoDBDocumentClient,
  tableName: string,
): Promise<StoreJtiResult> {
  try {
    await dynamoClient.send(
      new PutCommand({
        TableName: tableName,
        Item: {
          jti,
          client_id: clientId,
          ttl,
        },
        ConditionExpression: 'attribute_not_exists(jti)',
      }),
    );

    return { stored: true };
  } catch (error: unknown) {
    if (error instanceof ConditionalCheckFailedException) {
      return { stored: false, reason: 'replay' };
    }

    throw new DynamoError(
      `Failed to store JTI "${jti}" in table "${tableName}"`,
      error,
    );
  }
}
