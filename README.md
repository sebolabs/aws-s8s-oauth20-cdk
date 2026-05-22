# NHS PCA OAuth 2.0 PoC — AWS-Native (No Cognito)

## Overview

This PoC implements the NHS PCA OAuth 2.0 pattern using AWS-native services only — no Cognito. It demonstrates the **OAuth 2.0 client credentials grant** with `private_key_jwt` client authentication, securing system-to-system communication between a PCA (Emulator) and a PEP.

Input: https://digital.nhs.uk/developer/api-catalogue/patient-care-aggregator-get-appointments/authorisation-using-oauth-2.0

**Two stacks:**

| Stack | Purpose |
|-------|---------|
| `AwsS8sOauthAndApiStack` | PEP — Auth Server, Lambda Authorizer, mock Appointments integration, DynamoDB tables, KMS key, API Gateway |
| `NhsPcaEmulatorStack` | PCA Emulator — test client Lambda, KMS key, API Gateway |

**Three Lambda functions:**

| Function | Role |
|----------|------|
| `vhe-oauth-poc-auth-server` | OAuth 2.0 authorization server — validates client assertions, issues RS256-signed access tokens (180 s TTL) |
| `vhe-oauth-poc-lambda-authorizer` | REQUEST-type Lambda authorizer — verifies access tokens directly via KMS (no JWKS endpoint on PEP side) |
| `vhe-oauth-poc-pca-lambda` | PCA Emulator — builds signed client assertions, requests tokens, calls the Appointments API |

**AWS services:** API Gateway (REST), Lambda (Node.js 22.x, arm64), KMS (RSA_2048 asymmetric signing), DynamoDB (JTI replay store + client registry), CloudWatch Logs (structured JSON events).

**Key design decisions:**

- RS256 signing via KMS — no private key material in Lambda memory
- JTI replay protection via DynamoDB conditional writes (`attribute_not_exists(jti)`)
- Lambda Authorizer verifies access tokens directly via `kms:GetPublicKey` — no JWKS endpoint needed on the PEP side
- Client registry seeded via CDK custom resource (client_id: `vhe-oauth-poc-pca-client`)
- Authorizer caching disabled (TTL 0) to simplify replay-attack testing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  NhsPcaEmulatorStack                                                            │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  PCA API Gateway  (vhe-oauth-poc-pca-api)                                │   │
│  │  POST /token          ──► PCA_Lambda                                     │   │
│  │  POST /appointments   ──► PCA_Lambda                                     │   │
│  │  GET  /.well-known/jwks.json ──► PCA_Lambda                              │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                │                                                                │
│  ┌─────────────▼──────────────────────────────────────────────────────────┐     │
│  │  PCA_Lambda  (vhe-oauth-poc-pca-lambda)                                │     │
│  │  • Builds Client_Assertion JWT (iss/sub = client_id, aud = token URL)  │     │
│  │  • Signs via PCA KMS key (RS256)                                       │     │
│  │  • Calls PEP Token_Endpoint ───────────────────────────────────────►   │     │
│  │  • Calls PEP Appointments_Endpoint ────────────────────────────────►   │     │
│  │  • Serves own JWKS (/.well-known/jwks.json)                            │     │
│  └────────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  PCA KMS Key  (vhe-oauth-poc-pca-signing-key)  RSA_2048 SIGN_VERIFY     │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
                    │ POST /oauth2/token          │ GET /appointments
                    ▼                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  AwsS8sOauthAndApiStack                                                         │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  PEP API Gateway  (vhe-oauth-poc-pep-api)                                │   │
│  │  POST /oauth2/token          ──► Auth_Server Lambda (proxy)              │   │
│  │  GET  /appointments          ──► Lambda_Authorizer ──► Mock Integration  │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│          │                                │                                     │
│  ┌───────▼──────────────────┐   ┌─────────▼──────────────────────────────┐      │
│  │  Auth_Server Lambda      │   │  Lambda_Authorizer                     │      │
│  │  (vhe-oauth-poc-auth-    │   │  (vhe-oauth-poc-lambda-authorizer)     │      │
│  │   server)                │   │  • Extracts Bearer token               │      │
│  │  • Validates params      │   │  • Verifies RS256 sig via KMS          │      │
│  │  • Looks up Client_Reg   │   │  • Validates exp/scope/iss/aud         │      │
│  │  • Fetches/caches JWKS   │   │  • Returns IAM allow/deny policy       │      │
│  │  • Verifies assertion    │   └────────────────────────────────────────┘      │
│  │  • Checks JTI replay     │                                                   │
│  │  • Signs token via KMS   │                                                   │
│  └──────────────────────────┘                                                   │
│          │                                                                      │
│  ┌───────▼──────────────────────────────────────────────────────────────────┐   │
│  │  PEP KMS Key  (vhe-oauth-poc-pep-signing-key)  RSA_2048 SIGN_VERIFY      │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│  ┌──────────────────────────────┐  ┌──────────────────────────────────────┐     │
│  │  JTI_Store DynamoDB          │  │  Client_Registry DynamoDB            │     │
│  │  (vhe-oauth-poc-jti-store)   │  │  (vhe-oauth-poc-client-registry)     │     │
│  │  PK: jti | TTL: ttl          │  │  PK: client_id                       │     │
│  └──────────────────────────────┘  └──────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### High-level design (with test flow)

![HLD](hld.png "High-level design (with test flow)")

### Request Flow

```
1. Tester ──POST /token──► PCA APIG ──► PCA_Lambda
2. PCA_Lambda builds Client_Assertion JWT, signs via PCA KMS (RS256)
3. PCA_Lambda ──POST /oauth2/token──► PEP APIG ──► Auth_Server Lambda
4. Auth_Server: validate params → lookup client → fetch JWKS → verify sig → validate claims → check JTI replay → sign access token via PEP KMS
5. Auth_Server returns { access_token, token_type: "Bearer", expires_in: 180 }
6. PCA_Lambda returns token response to tester

7. Tester ──POST /appointments { access_token }──► PCA APIG ──► PCA_Lambda
8. PCA_Lambda ──GET /appointments (Bearer token)──► PEP APIG ──► Lambda_Authorizer
9. Lambda_Authorizer: extract Bearer → verify RS256 sig via KMS → validate exp/scope/iss/aud → return IAM allow
10. PEP APIG ──► Mock Integration returns { "resourceType": "Bundle", "entry": [] }
11. Response flows back to tester
```

---

## Prerequisites

- **AWS CLI** v2 configured with credentials that have permissions to deploy CloudFormation, Lambda, API Gateway, DynamoDB, KMS, IAM, and CloudWatch resources
- **Node.js** ≥ 22.x
- **AWS CDK CLI** ≥ 2.x (`npm install -g aws-cdk`)
- **Region**: Both stacks target `eu-west-2` (London)

> **Note:** The PCA client (`vhe-oauth-poc-pca-client`) is automatically pre-registered in the Client_Registry DynamoDB table via a CDK custom resource during deployment. No manual DynamoDB seeding is required.

---

## Deployment

Deploy the PEP stack first (the PCA stack depends on its outputs):

```bash
# 1. Install dependencies
npm install

# 2. Bootstrap CDK (first time only)
# The qualifier  is configured in cdk.json (@aws-cdk/core:bootstrapQualifier)
cdk bootstrap aws://<AWS_ACCOUNT_ID>/eu-west-2 --qualifier <qualifier>

# 3. Deploy PEP stack
cdk deploy AwsS8sOauthAndApiStack --require-approval never

# 4. Deploy PCA Emulator stack
# This also automatically registers the PCA client in the PEP Client_Registry
# DynamoDB table via a CDK custom resource — no manual setup needed.
cdk deploy NhsPcaEmulatorStack --require-approval never
```

> **No manual DynamoDB setup required.** Deploying the PCA stack automatically seeds the PEP `Client_Registry` table with the PCA client record (`vhe-oauth-poc-pca-client`). The system is fully functional immediately after deployment.

### Capture CloudFormation Outputs

After deployment, capture the API Gateway URLs needed for testing:

```bash
# PEP stack outputs
PEP_APIG_URL=$(aws cloudformation describe-stacks \
  --stack-name AwsS8sOauthAndApiStack \
  --query "Stacks[0].Outputs[?OutputKey=='PepApiUrl'].OutputValue" \
  --output text \
  --region eu-west-2)

# PCA stack outputs
PCA_APIG_URL=$(aws cloudformation describe-stacks \
  --stack-name NhsPcaEmulatorStack \
  --query "Stacks[0].Outputs[?OutputKey=='PcaApiUrl'].OutputValue" \
  --output text \
  --region eu-west-2)

echo "PEP API: $PEP_APIG_URL"
echo "PCA API: $PCA_APIG_URL"
```

### Tear Down

```bash
cdk destroy NhsPcaEmulatorStack --force
cdk destroy AwsS8sOauthAndApiStack --force
```

All resources (DynamoDB tables, KMS keys, log groups) have `removalPolicy: DESTROY` and will be cleaned up.

---

## Testing

### Happy Path

#### 1. Request an Access Token

```bash
curl -s -X POST $PCA_APIG_URL/token \
  -H "Content-Type: application/json" \
  -w "\n%{http_code}" | tee /tmp/token_response.json
```

**Expected:** HTTP 200 with body containing `access_token`, `token_type: "Bearer"`, `expires_in: 180`.

Output example:

```json
{
	"access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNiMGQxOTMyLTgwMzAtNGYwMi1iNTI3LTRkMzY2YzAyZjE1OSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovLzkzcjE2OXNpM2kuZXhlY3V0ZS1hcGkuZXUtd2VzdC0yLmFtYXpvbmF3cy5jb20vdjE<trimmed>.hCa08KB3qX9WjrMOJm1W3m_LCJP7l8jnRIlJu6kS9R_Nja3CsOA7OmyG9V6icyU-VwBzwBu7h8R_Y9HSIhRglp9<trimmed>",
	"token_type": "Bearer",
	"expires_in": 180
}
200
```

Extract the access token:

```bash
ACCESS_TOKEN=$(cat /tmp/token_response.json | head -1 | jq -r '.access_token')
echo "Access Token: ${ACCESS_TOKEN:0:50}..."
```

Access Token (decoded payload) example:

```json
{
  "iss": "https://0123456789.execute-api.eu-west-2.amazonaws.com/v1/oauth2/token",
  "sub": "vhe-oauth-poc-pca-client",
  "aud": "https://0123456789.execute-api.eu-west-2.amazonaws.com/v1/appointments",
  "exp": 1779396043,
  "iat": 1779395863,
  "jti": "d8bacb8a-24fa-4a68-806a-a33742307e5a",
  "scope": "appointments:read"
}
```

#### 2. Call the Appointments API

```bash
curl -s -X POST $PCA_APIG_URL/appointments \
  -H "Content-Type: application/json" \
  -d "{\"access_token\": \"$ACCESS_TOKEN\"}" \
  -w "\n%{http_code}"
```

**Expected:** HTTP 200 with body `{"resourceType":"Bundle","entry":[]}`.

Output example:

```
{
	"resourceType": "Bundle",
	"entry": []
}
200
```

#### 3. Verify e2e trace in CloudWatch Logs

The `x-amzn-requestid` response header from step 1 is the correlation ID. Use it to query all log events across all three components:

```bash
aws logs start-query \
  --log-group-names \
    "/aws/lambda/vhe-oauth-poc-pca-lambda" \
    "/aws/lambda/vhe-oauth-poc-auth-server" \
    "/aws/lambda/vhe-oauth-poc-lambda-authorizer" \
  --start-time $(date -d '5 minutes ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, level, event, component, correlation_id | filter correlation_id = "<CORRELATION_ID>" | sort @timestamp asc' \
  --region eu-west-2
```

> **Note:** Replace `<CORRELATION_ID>` with the API Gateway request ID returned in the `x-amzn-requestid` response header from the PCA API call.

---

### Unhappy Paths

#### Scenario 1: Replay Attack

The PCA Lambda generates a unique JTI per invocation, so to test replay you need to call `/token` twice in rapid succession (each call generates its own JTI — replay is detected at the Auth_Server level if the same assertion is resubmitted).

```bash
# First call — should succeed (HTTP 200)
curl -s -X POST $PCA_APIG_URL/token -H "Content-Type: application/json" -w "\n%{http_code}"

# To test JTI replay, POST the same client_assertion directly to the PEP token endpoint:
# (Capture the client_assertion from PCA Lambda logs or construct one manually)
# The second submission of the same JTI will be rejected.
curl -s -X POST $PEP_APIG_URL/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_id=vhe-oauth-poc-pca-client&client_assertion=<CAPTURED_CLIENT_ASSERTION>" \
  -w "\n%{http_code}"
```

**Expected:** HTTP 401 with `{"error":"invalid_client","error_description":"..."}`.  
**Log event to verify:** `JTI_REPLAY_DETECTED` in `/aws/lambda/vhe-oauth-poc-auth-server`.

---

#### Scenario 2: Expired Token

```bash
# 1. Obtain a token
ACCESS_TOKEN=$(curl -s -X POST $PCA_APIG_URL/token -H "Content-Type: application/json" | jq -r '.access_token')

# 2. Wait for token to expire (180s TTL + clock skew tolerance)
echo "Waiting 181 seconds for token to expire..."
sleep 181

# 3. Attempt to use the expired token
curl -s -X POST $PCA_APIG_URL/appointments \
  -H "Content-Type: application/json" \
  -d "{\"access_token\": \"$ACCESS_TOKEN\"}" \
  -w "\n%{http_code}"
```

**Expected:** HTTP 401 (the PEP API Gateway returns 403 when the Lambda Authorizer denies; the PCA Lambda maps 401/403 to 401 for the caller).  
**Log event to verify:** `CLAIMS_VALIDATION_FAILED` (with `failed_claim: "exp"`) in `/aws/lambda/vhe-oauth-poc-lambda-authorizer`.

---

#### Scenario 3: Invalid Token (Tampered Signature)

```bash
# Call the PEP Appointments endpoint directly with a tampered Bearer token
curl -s -X GET $PEP_APIG_URL/appointments \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.INVALID_SIGNATURE" \
  -w "\n%{http_code}"
```

**Expected:** HTTP 403 with `{"error":"access_denied","error_description":"Access denied"}`.  
API Gateway returns 403 when the Lambda Authorizer returns a Deny policy.  
**Log event to verify:** `TOKEN_SIGNATURE_INVALID` in `/aws/lambda/vhe-oauth-poc-lambda-authorizer`.

---

#### Scenario 4: Missing Token

```bash
# Call the PEP Appointments endpoint with no Authorization header
curl -s -X GET $PEP_APIG_URL/appointments \
  -w "\n%{http_code}"
```

**Expected:** HTTP 401 with `{"error":"unauthorized","error_description":"Access denied"}`.  
API Gateway returns 401 when the identity source (Authorization header) is missing — the authorizer is not invoked.  
**Log event to verify:** No Lambda Authorizer invocation (API Gateway rejects before calling the authorizer).

---

#### Scenario 5: Unknown Client

```bash
# POST directly to the PEP token endpoint with an unregistered client_id
curl -s -X POST $PEP_APIG_URL/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_id=unknown-client-id&client_assertion=eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJ1bmtub3duLWNsaWVudC1pZCJ9.fake" \
  -w "\n%{http_code}"
```

**Expected:** HTTP 401 with `{"error":"invalid_client","error_description":"..."}`.  
**Log event to verify:** `CLIENT_NOT_FOUND` in `/aws/lambda/vhe-oauth-poc-auth-server`.

---

### CloudWatch Logs Insights Query Template

Use this query to trace any request end-to-end across all three Lambda functions:

```
fields @timestamp, level, event, component, correlation_id
| filter correlation_id = "<CORRELATION_ID>"
| sort @timestamp asc
```

> `<CORRELATION_ID>` is the API Gateway request ID returned in the `x-amzn-requestid` response header of the initial PCA API call. This ID propagates through all downstream Lambda invocations via `event.requestContext.requestId`.

---

## Project Structure

```
├── bin/                          # CDK app entry point
├── lib/
│   ├── aws-s8s-oauth-and-api-stack.ts   # PEP stack (Auth_Server, Authorizer, APIG, DynamoDB, KMS)
│   └── nhs-pca-emulator-stack.ts        # PCA Emulator stack (PCA_Lambda, APIG, KMS)
├── src/
│   ├── shared/                   # Shared utilities (logger, JWT helpers)
│   └── lambdas/
│       ├── auth-server/          # OAuth 2.0 authorization server
│       ├── lambda-authorizer/    # REQUEST-type Lambda authorizer
│       └── pca-lambda/           # PCA Emulator (test client)
├── test/
│   ├── unit/                     # Unit tests (mirrors src/ structure)
│   └── integration/              # End-to-end integration tests
├── cdk.json
└── README.md
```

---

## Design Notes

- **No JWKS endpoint on PEP side:** The Lambda Authorizer verifies access tokens directly via `kms:GetPublicKey` with a 60-minute in-memory cache. This eliminates the need for a JWKS endpoint on the PEP API Gateway — the authorizer trusts the KMS key it already has access to.
- **Authorizer caching disabled:** The Lambda Authorizer result TTL is set to 0 seconds. This ensures every request triggers a fresh token validation, which is necessary for testing replay attacks and token expiry scenarios.
- **DynamoDB TTL for JTI cleanup:** JTI entries expire automatically via DynamoDB TTL (set to the `exp` claim of the client assertion). No manual cleanup is needed.
