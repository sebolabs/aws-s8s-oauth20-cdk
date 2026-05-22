/**
 * Shared structured logger utility.
 *
 * Emits single-line JSON log events to stdout conforming to the schema
 * defined in Requirement 9.1 and the design's Structured Log Event Schema.
 *
 * Feature: oauth2-apig-poc
 */

export type LogLevel = 'INFO' | 'WARN' | 'ERROR';

export type LogComponent = 'AUTH_SERVER' | 'LAMBDA_AUTHORIZER' | 'PCA_LAMBDA';

const VALID_LEVELS = new Set<LogLevel>(['INFO', 'WARN', 'ERROR']);
const EVENT_PATTERN = /^[A-Z][A-Z0-9_]+$/;

/**
 * Emit a single-line structured JSON log event.
 *
 * @param level        - Log severity: INFO | WARN | ERROR
 * @param event        - Machine-readable event name in SCREAMING_SNAKE_CASE (e.g. TOKEN_REQUEST_RECEIVED)
 * @param component    - Emitting component: AUTH_SERVER | LAMBDA_AUTHORIZER | PCA_LAMBDA
 * @param correlationId - API Gateway request ID propagated across all components
 * @param extra        - Optional additional fields merged into the log line
 *
 * @throws {Error} if level or event fail validation
 */
export function log(
  level: LogLevel,
  event: string,
  component: LogComponent,
  correlationId: string,
  extra?: Record<string, unknown>,
): void {
  if (!VALID_LEVELS.has(level)) {
    throw new Error(`Invalid log level "${level}". Must be one of: INFO, WARN, ERROR`);
  }

  if (!EVENT_PATTERN.test(event)) {
    throw new Error(
      `Invalid event name "${event}". Must match [A-Z][A-Z0-9_]+ (SCREAMING_SNAKE_CASE starting with a letter)`,
    );
  }

  const entry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    level,
    event,
    component,
    correlation_id: correlationId,
    ...extra,
  };

  // Single-line JSON — no pretty-printing
  process.stdout.write(JSON.stringify(entry) + '\n');
}
