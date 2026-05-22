import * as cdk from 'aws-cdk-lib';
import { CfnOutput, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import { Construct } from 'constructs';
import * as path from 'path';

/**
 * AwsS8sOauthAndApiStack — PEP stack
 *
 * Defines the Patient Engagement Portal (PEP) infrastructure:
 * - KMS signing key (vhe-oauth-poc-pep-signing-key)
 * - DynamoDB JTI_Store and Client_Registry tables
 * - Auth_Server and Lambda_Authorizer Lambda functions
 * - CloudWatch Log Groups
 * - PEP API Gateway (REST)
 * - IAM roles
 */
export class AwsS8sOauthAndApiStack extends cdk.Stack {
  /** PEP RSA signing key used by Auth_Server to sign Access_Tokens */
  public readonly pepSigningKey: kms.Key;

  /** DynamoDB table for JTI replay protection */
  public readonly jtiStoreTable: dynamodb.Table;

  /** DynamoDB table for client registration records */
  public readonly clientRegistryTable: dynamodb.Table;

  /** IAM execution role for the Auth_Server Lambda */
  public readonly authServerRole: iam.Role;

  /** IAM execution role for the Lambda_Authorizer */
  public readonly lambdaAuthorizerRole: iam.Role;

  /** Auth_Server Lambda function */
  public readonly authServerFn: NodejsFunction;

  /** Lambda_Authorizer Lambda function */
  public readonly lambdaAuthorizerFn: NodejsFunction;

  /** PEP API Gateway base URL (for cross-stack references) */
  public readonly pepApiUrl: string;

  /** PEP Token Endpoint URL */
  public readonly pepTokenEndpointUrl: string;

  /** PEP Appointments Endpoint URL */
  public readonly pepAppointmentsUrl: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // -------------------------------------------------------------------------
    // KMS Key — PEP signing key (RSA_2048, SIGN_VERIFY)
    // -------------------------------------------------------------------------
    this.pepSigningKey = new kms.Key(this, 'PepSigningKey', {
      keySpec: kms.KeySpec.RSA_2048,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: 'alias/vhe-oauth-poc-pep-signing-key',
      description: 'RSA signing key for vhe-oauth-poc PEP',
      enableKeyRotation: false, // rotation not supported for asymmetric keys
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
    });

    // -------------------------------------------------------------------------
    // DynamoDB — JTI_Store (replay protection)
    // -------------------------------------------------------------------------
    this.jtiStoreTable = new dynamodb.Table(this, 'JtiStoreTable', {
      tableName: 'vhe-oauth-poc-jti-store',
      partitionKey: { name: 'jti', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------------
    // DynamoDB — Client_Registry
    // -------------------------------------------------------------------------
    this.clientRegistryTable = new dynamodb.Table(this, 'ClientRegistryTable', {
      tableName: 'vhe-oauth-poc-client-registry',
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------------
    // Log group ARN helpers (log groups are created in task 2.2)
    // -------------------------------------------------------------------------
    const authServerLogGroupArn = `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/vhe-oauth-poc-auth-server:*`;
    const lambdaAuthorizerLogGroupArn = `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/vhe-oauth-poc-lambda-authorizer:*`;

    // -------------------------------------------------------------------------
    // IAM Role — Auth_Server Lambda execution role
    // -------------------------------------------------------------------------
    this.authServerRole = new iam.Role(this, 'AuthServerRole', {
      roleName: 'vhe-oauth-poc-auth-server-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: {
        'auth-server-policy': new iam.PolicyDocument({
          statements: [
            // CloudWatch Logs — write to the auth-server log group only
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: [authServerLogGroupArn],
            }),
            // KMS — sign tokens and expose public key
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['kms:Sign', 'kms:GetPublicKey'],
              resources: [this.pepSigningKey.keyArn],
            }),
            // DynamoDB — read from both tables
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['dynamodb:GetItem'],
              resources: [
                this.jtiStoreTable.tableArn,
                this.clientRegistryTable.tableArn,
              ],
            }),
            // DynamoDB — write JTI entries (replay protection)
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['dynamodb:PutItem'],
              resources: [this.jtiStoreTable.tableArn],
            }),
          ],
        }),
      },
    });

    // -------------------------------------------------------------------------
    // IAM Role — Lambda_Authorizer execution role
    // -------------------------------------------------------------------------
    this.lambdaAuthorizerRole = new iam.Role(this, 'LambdaAuthorizerRole', {
      roleName: 'vhe-oauth-poc-lambda-authorizer-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: {
        'lambda-authorizer-policy': new iam.PolicyDocument({
          statements: [
            // CloudWatch Logs — write to the lambda-authorizer log group only
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: [lambdaAuthorizerLogGroupArn],
            }),
            // KMS — retrieve public key for token verification (no signing)
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['kms:GetPublicKey'],
              resources: [this.pepSigningKey.keyArn],
            }),
          ],
        }),
      },
    });

    // -------------------------------------------------------------------------
    // CloudWatch Log Groups (created before Lambda functions)
    // -------------------------------------------------------------------------
    const authServerLogGroup = new logs.LogGroup(this, 'AuthServerLogGroup', {
      logGroupName: '/aws/lambda/vhe-oauth-poc-auth-server',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const lambdaAuthorizerLogGroup = new logs.LogGroup(this, 'LambdaAuthorizerLogGroup', {
      logGroupName: '/aws/lambda/vhe-oauth-poc-lambda-authorizer',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------------
    // Lambda — Auth_Server
    // -------------------------------------------------------------------------
    this.authServerFn = new NodejsFunction(this, 'AuthServerFn', {
      functionName: 'vhe-oauth-poc-auth-server',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(15),
      role: this.authServerRole,
      entry: path.join(__dirname, '..', 'src', 'lambdas', 'auth-server', 'index.ts'),
      handler: 'handler',
      logGroup: authServerLogGroup,
      bundling: {
        minify: false,
        sourceMap: true,
      },
      environment: {
        KMS_KEY_ID: this.pepSigningKey.keyId,
        JTI_TABLE_NAME: this.jtiStoreTable.tableName,
        CLIENT_REGISTRY_TABLE_NAME: this.clientRegistryTable.tableName,
        TOKEN_ENDPOINT_URL: '', // wired after API Gateway is created
        APPOINTMENTS_ENDPOINT_URL: '', // wired after API Gateway is created
        CLOCK_SKEW_TOLERANCE_SECONDS: '10',
        JWKS_CACHE_TTL_SECONDS: '3600',
      },
    });

    // -------------------------------------------------------------------------
    // Lambda — Lambda_Authorizer
    // -------------------------------------------------------------------------
    this.lambdaAuthorizerFn = new NodejsFunction(this, 'LambdaAuthorizerFn', {
      functionName: 'vhe-oauth-poc-lambda-authorizer',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 128,
      timeout: Duration.seconds(10),
      role: this.lambdaAuthorizerRole,
      entry: path.join(__dirname, '..', 'src', 'lambdas', 'lambda-authorizer', 'index.ts'),
      handler: 'handler',
      logGroup: lambdaAuthorizerLogGroup,
      bundling: {
        minify: false,
        sourceMap: true,
      },
      environment: {
        KMS_KEY_ID: this.pepSigningKey.keyId,
        TOKEN_ENDPOINT_URL: '', // wired after API Gateway is created
        APPOINTMENTS_ENDPOINT_URL: '', // wired after API Gateway is created
        CLOCK_SKEW_TOLERANCE_SECONDS: '10',
        KMS_KEY_CACHE_TTL_SECONDS: '3600',
      },
    });

    // -------------------------------------------------------------------------
    // API Gateway — PEP REST API (vhe-oauth-poc-pep-api)
    // -------------------------------------------------------------------------
    const pepApi = new apigateway.RestApi(this, 'PepApi', {
      restApiName: 'vhe-oauth-poc-pep-api',
      description: 'PEP OAuth 2.0 API Gateway',
      deployOptions: {
        stageName: 'v1',
      },
    });

    // --- Default gateway responses (JSON error bodies) ---
    pepApi.addGatewayResponse('Default4xx', {
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: {
        'Content-Type': "'application/json'",
      },
      templates: {
        'application/json': JSON.stringify({
          error: 'client_error',
          error_description: '$context.error.messageString',
        }),
      },
    });

    pepApi.addGatewayResponse('Default5xx', {
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: {
        'Content-Type': "'application/json'",
      },
      templates: {
        'application/json': JSON.stringify({
          error: 'server_error',
          error_description: '$context.error.messageString',
        }),
      },
    });

    pepApi.addGatewayResponse('Unauthorized', {
      type: apigateway.ResponseType.UNAUTHORIZED,
      statusCode: '401',
      responseHeaders: {
        'Content-Type': "'application/json'",
      },
      templates: {
        'application/json': JSON.stringify({
          error: 'unauthorized',
          error_description: 'Access denied',
        }),
      },
    });

    pepApi.addGatewayResponse('AccessDenied', {
      type: apigateway.ResponseType.ACCESS_DENIED,
      statusCode: '403',
      responseHeaders: {
        'Content-Type': "'application/json'",
      },
      templates: {
        'application/json': JSON.stringify({
          error: 'access_denied',
          error_description: 'Access denied',
        }),
      },
    });

    // --- Lambda Authorizer (REQUEST type, no caching) ---
    const authorizer = new apigateway.RequestAuthorizer(this, 'PepLambdaAuthorizer', {
      handler: this.lambdaAuthorizerFn,
      identitySources: [apigateway.IdentitySource.header('Authorization')],
      resultsCacheTtl: Duration.seconds(0),
      authorizerName: 'vhe-oauth-poc-lambda-authorizer',
    });

    // --- Route: POST /oauth2/token → Auth_Server Lambda proxy ---
    const oauth2Resource = pepApi.root.addResource('oauth2');
    const tokenResource = oauth2Resource.addResource('token');
    tokenResource.addMethod(
      'POST',
      new apigateway.LambdaIntegration(this.authServerFn, { proxy: true }),
    );

    // --- Route: GET /appointments → Mock integration with Lambda_Authorizer ---
    const appointmentsResource = pepApi.root.addResource('appointments');
    appointmentsResource.addMethod(
      'GET',
      new apigateway.MockIntegration({
        integrationResponses: [
          {
            statusCode: '200',
            responseTemplates: {
              'application/json': JSON.stringify({ resourceType: 'Bundle', entry: [] }),
            },
          },
        ],
        requestTemplates: {
          'application/json': '{"statusCode": 200}',
        },
      }),
      {
        authorizer,
        authorizationType: apigateway.AuthorizationType.CUSTOM,
        methodResponses: [
          {
            statusCode: '200',
            responseModels: {
              'application/json': apigateway.Model.EMPTY_MODEL,
            },
          },
        ],
      },
    );

    // --- Route: /{proxy+} catch-all → 404 ---
    const proxyResource = pepApi.root.addResource('{proxy+}');
    proxyResource.addMethod(
      'ANY',
      new apigateway.MockIntegration({
        integrationResponses: [
          {
            statusCode: '404',
            responseTemplates: {
              'application/json': JSON.stringify({ error: 'not_found', error_description: 'Resource not found' }),
            },
          },
        ],
        requestTemplates: {
          'application/json': '{"statusCode": 404}',
        },
      }),
      {
        methodResponses: [
          {
            statusCode: '404',
            responseModels: {
              'application/json': apigateway.Model.EMPTY_MODEL,
            },
          },
        ],
      },
    );

    // -------------------------------------------------------------------------
    // Wire endpoint URLs into Lambda environment variables
    // -------------------------------------------------------------------------
    // Construct URLs manually to avoid circular dependency between API GW and Lambdas.
    // We use the restApiId (no dependency on deployment) and hardcode the stage name
    // since it's defined as 'v1' in deployOptions above.
    const stageName = 'v1';
    const tokenEndpointUrl = cdk.Fn.join('', [
      'https://',
      pepApi.restApiId,
      '.execute-api.',
      this.region,
      '.amazonaws.com/',
      stageName,
      '/oauth2/token',
    ]);
    const appointmentsEndpointUrl = cdk.Fn.join('', [
      'https://',
      pepApi.restApiId,
      '.execute-api.',
      this.region,
      '.amazonaws.com/',
      stageName,
      '/appointments',
    ]);

    this.authServerFn.addEnvironment('TOKEN_ENDPOINT_URL', tokenEndpointUrl);
    this.authServerFn.addEnvironment('APPOINTMENTS_ENDPOINT_URL', appointmentsEndpointUrl);
    this.lambdaAuthorizerFn.addEnvironment('TOKEN_ENDPOINT_URL', tokenEndpointUrl);
    this.lambdaAuthorizerFn.addEnvironment('APPOINTMENTS_ENDPOINT_URL', appointmentsEndpointUrl);

    // -------------------------------------------------------------------------
    // CloudFormation Outputs
    // -------------------------------------------------------------------------
    const pepApiBaseUrl = cdk.Fn.join('', [
      'https://',
      pepApi.restApiId,
      '.execute-api.',
      this.region,
      '.amazonaws.com/',
      stageName,
      '/',
    ]);

    new CfnOutput(this, 'PepApiUrl', {
      value: pepApiBaseUrl,
      description: 'PEP API Gateway base URL',
      exportName: 'PepApiUrl',
    });

    new CfnOutput(this, 'PepAppointmentsUrl', {
      value: appointmentsEndpointUrl,
      description: 'PEP Appointments Endpoint URL',
      exportName: 'PepAppointmentsUrl',
    });

    new CfnOutput(this, 'PepTokenEndpointUrl', {
      value: tokenEndpointUrl,
      description: 'PEP OAuth 2.0 Token Endpoint URL',
      exportName: 'PepTokenEndpointUrl',
    });

    // Expose API for cross-stack references
    this.pepApiUrl = pepApiBaseUrl;
    this.pepAppointmentsUrl = appointmentsEndpointUrl;
    this.pepTokenEndpointUrl = tokenEndpointUrl;
  }
}
