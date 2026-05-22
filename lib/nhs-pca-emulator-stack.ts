import * as cdk from 'aws-cdk-lib';
import { CfnOutput, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';
import * as path from 'path';
import { AwsS8sOauthAndApiStack } from './aws-s8s-oauth-and-api-stack';

/**
 * NhsPcaEmulatorStack — PCA Emulator stack
 *
 * Defines the NHS Patient Care Aggregator (PCA) Emulator infrastructure:
 * - KMS signing key (vhe-oauth-poc-pca-signing-key)
 * - PCA_Lambda function
 * - CloudWatch Log Group
 * - PCA API Gateway (REST)
 * - IAM role
 *
 * Requirements: 14.1, 14.2, 14.3, 14.4, 15.1, 15.2, 15.4, 15.6, 15.7, 15.8, 15.9, 15.10
 */

export interface NhsPcaEmulatorStackProps extends cdk.StackProps {
  /** Reference to the PEP stack for cross-stack outputs */
  pepStack: AwsS8sOauthAndApiStack;
}

export class NhsPcaEmulatorStack extends cdk.Stack {
  /** PCA RSA signing key used by PCA_Lambda to sign Client_Assertions */
  public readonly pcaSigningKey: kms.Key;

  /** PCA API Gateway base URL */
  public readonly pcaApiUrl: string;

  constructor(scope: Construct, id: string, props: NhsPcaEmulatorStackProps) {
    super(scope, id, props);

    const { pepStack } = props;

    // -------------------------------------------------------------------------
    // KMS Key — PCA signing key (RSA_2048, SIGN_VERIFY)
    // -------------------------------------------------------------------------
    this.pcaSigningKey = new kms.Key(this, 'PcaSigningKey', {
      keySpec: kms.KeySpec.RSA_2048,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: 'alias/vhe-oauth-poc-pca-signing-key',
      description: 'RSA signing key for vhe-oauth-poc PCA Emulator',
      enableKeyRotation: false,
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
    });

    // -------------------------------------------------------------------------
    // CloudWatch Log Group
    // -------------------------------------------------------------------------
    const pcaLambdaLogGroup = new logs.LogGroup(this, 'PcaLambdaLogGroup', {
      logGroupName: '/aws/lambda/vhe-oauth-poc-pca-lambda',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // -------------------------------------------------------------------------
    // IAM Role — PCA_Lambda execution role
    // -------------------------------------------------------------------------
    const pcaLambdaLogGroupArn = `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/vhe-oauth-poc-pca-lambda:*`;

    const pcaLambdaRole = new iam.Role(this, 'PcaLambdaRole', {
      roleName: 'vhe-oauth-poc-pca-lambda-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: {
        'pca-lambda-policy': new iam.PolicyDocument({
          statements: [
            // CloudWatch Logs — write to the PCA lambda log group only
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: [pcaLambdaLogGroupArn],
            }),
            // KMS — sign assertions and expose public key
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['kms:Sign', 'kms:GetPublicKey'],
              resources: [this.pcaSigningKey.keyArn],
            }),
          ],
        }),
      },
    });

    // -------------------------------------------------------------------------
    // Lambda — PCA_Lambda
    // -------------------------------------------------------------------------
    const pcaLambdaFn = new NodejsFunction(this, 'PcaLambdaFn', {
      functionName: 'vhe-oauth-poc-pca-lambda',
      runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: Duration.seconds(30),
      role: pcaLambdaRole,
      entry: path.join(__dirname, '..', 'src', 'lambdas', 'pca-lambda', 'index.ts'),
      handler: 'handler',
      logGroup: pcaLambdaLogGroup,
      bundling: {
        minify: false,
        sourceMap: true,
      },
      environment: {
        PCA_KMS_KEY_ID: this.pcaSigningKey.keyId,
        PCA_CLIENT_ID: 'vhe-oauth-poc-pca-client',
        TOKEN_ENDPOINT_URL: pepStack.pepTokenEndpointUrl,
        APPOINTMENTS_ENDPOINT_URL: pepStack.pepAppointmentsUrl,
      },
    });

    // -------------------------------------------------------------------------
    // API Gateway — PCA REST API (vhe-oauth-poc-pca-api)
    // -------------------------------------------------------------------------
    const pcaApi = new apigateway.RestApi(this, 'PcaApi', {
      restApiName: 'vhe-oauth-poc-pca-api',
      description: 'PCA Emulator API Gateway',
      deployOptions: {
        stageName: 'v1',
      },
    });

    const pcaLambdaIntegration = new apigateway.LambdaIntegration(pcaLambdaFn, { proxy: true });

    // --- Route: POST /token → PCA_Lambda proxy ---
    const tokenResource = pcaApi.root.addResource('token');
    tokenResource.addMethod('POST', pcaLambdaIntegration);

    // --- Route: POST /appointments → PCA_Lambda proxy ---
    const appointmentsResource = pcaApi.root.addResource('appointments');
    appointmentsResource.addMethod('POST', pcaLambdaIntegration);

    // --- Route: GET /.well-known/jwks.json → PCA_Lambda proxy ---
    const wellKnownResource = pcaApi.root.addResource('.well-known');
    const jwksResource = wellKnownResource.addResource('jwks.json');
    jwksResource.addMethod('GET', pcaLambdaIntegration);

    // -------------------------------------------------------------------------
    // CloudFormation Outputs
    // -------------------------------------------------------------------------
    new CfnOutput(this, 'PcaApiUrl', {
      value: pcaApi.url,
      description: 'PCA Emulator API Gateway base URL',
      exportName: 'PcaApiUrl',
    });

    // Expose API URL for cross-stack references
    this.pcaApiUrl = pcaApi.url;

    // -------------------------------------------------------------------------
    // Seed Client_Registry with PCA client record (automates manual DDB setup)
    // -------------------------------------------------------------------------
    // Without this custom resource, you would need to manually run:
    //   aws dynamodb put-item --table-name vhe-oauth-poc-client-registry --item '{...}'
    // after every deployment to register the PCA client. This automates that step
    // so the system is fully functional immediately after `cdk deploy`.
    //
    // It inserts the PCA client record into the PEP Client_Registry DynamoDB table
    // with the JWKS URI pointing to the PCA emulator's /.well-known/jwks.json endpoint.
    // Placed in the PCA stack (rather than PEP) to avoid a circular cross-stack
    // dependency: PCA depends on PEP for endpoint URLs, and the seed needs the PCA API URL.
    //
    // Requirements: 5.1, 5.2, 14.5
    const seedClientRegistry = new cr.AwsCustomResource(this, 'SeedClientRegistry', {
      onCreate: {
        service: 'DynamoDB',
        action: 'putItem',
        parameters: {
          TableName: pepStack.clientRegistryTable.tableName,
          Item: {
            client_id: { S: 'vhe-oauth-poc-pca-client' },
            jwks_uri: { S: `${pcaApi.url}.well-known/jwks.json` },
            allowed_scopes: { S: 'appointments:read' },
            status: { S: 'active' },
          },
        },
        physicalResourceId: cr.PhysicalResourceId.of('vhe-oauth-poc-pca-client-seed'),
      },
      onUpdate: {
        service: 'DynamoDB',
        action: 'putItem',
        parameters: {
          TableName: pepStack.clientRegistryTable.tableName,
          Item: {
            client_id: { S: 'vhe-oauth-poc-pca-client' },
            jwks_uri: { S: `${pcaApi.url}.well-known/jwks.json` },
            allowed_scopes: { S: 'appointments:read' },
            status: { S: 'active' },
          },
        },
        physicalResourceId: cr.PhysicalResourceId.of('vhe-oauth-poc-pca-client-seed'),
      },
      onDelete: {
        service: 'DynamoDB',
        action: 'deleteItem',
        parameters: {
          TableName: pepStack.clientRegistryTable.tableName,
          Key: {
            client_id: { S: 'vhe-oauth-poc-pca-client' },
          },
        },
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['dynamodb:PutItem', 'dynamodb:DeleteItem'],
          resources: [pepStack.clientRegistryTable.tableArn],
        }),
      ]),
    });
  }
}
