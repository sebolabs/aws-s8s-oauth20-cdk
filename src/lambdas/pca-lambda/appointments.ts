/**
 * PCA appointments proxy handler — pure module.
 *
 * Parses the incoming JSON body to extract an access_token, then calls the
 * upstream Appointments_Endpoint with a Bearer token. Returns the upstream
 * response mapped to the appropriate HTTP status code.
 *
 * Feature: oauth2-apig-poc
 * Requirements: 13.1, 13.2, 13.3, 13.4, 13.5
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ApiGatewayProxyResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Handle a POST /appointments request from the PCA API Gateway.
 *
 * @param body - Raw string body from the API Gateway event (JSON with access_token)
 * @param appointmentsEndpointUrl - The upstream Appointments_Endpoint URL to call
 * @returns API Gateway proxy response object
 */
export async function handleAppointments(
  body: string | null | undefined,
  appointmentsEndpointUrl: string,
): Promise<ApiGatewayProxyResponse> {
  // Step 1: Parse JSON body and extract access_token
  let accessToken: string | undefined;

  try {
    const parsed = JSON.parse(body || '');
    accessToken = parsed?.access_token;
  } catch {
    return buildResponse(400, {
      error: 'invalid_request',
      error_description: 'Request body must be valid JSON',
    });
  }

  if (!accessToken || (typeof accessToken === 'string' && accessToken.trim() === '')) {
    return buildResponse(400, {
      error: 'invalid_request',
      error_description: 'access_token field is required in the request body',
    });
  }

  // Step 2: Call GET on the Appointments_Endpoint with Bearer token
  let upstreamResponse: Response;
  try {
    upstreamResponse = await fetch(appointmentsEndpointUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
  } catch {
    // Network or other fetch error → 502
    return buildResponse(502, {
      error: 'bad_gateway',
      error_description: 'Failed to reach the upstream appointments endpoint',
    });
  }

  // Step 3: Map upstream response to appropriate status code
  const upstreamBody = await upstreamResponse.text();

  if (upstreamResponse.status === 200) {
    // On 200: return 200 with response body
    return buildResponse(200, upstreamBody);
  }

  if (upstreamResponse.status === 401 || upstreamResponse.status === 403) {
    // On 401/403: return 401 with upstream error body
    // API Gateway returns 403 when the Lambda Authorizer denies (e.g. expired token),
    // which from the client's perspective is an authorization failure (401).
    return buildResponse(401, upstreamBody);
  }

  // On other error: return 502
  return buildResponse(502, {
    error: 'bad_gateway',
    error_description: 'Upstream appointments endpoint returned an error',
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildResponse(statusCode: number, body: unknown): ApiGatewayProxyResponse {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  };
}
