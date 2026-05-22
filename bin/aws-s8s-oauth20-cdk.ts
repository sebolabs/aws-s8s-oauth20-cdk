#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsS8sOauthAndApiStack } from '../lib/aws-s8s-oauth-and-api-stack';
import { NhsPcaEmulatorStack } from '../lib/nhs-pca-emulator-stack';

const app = new cdk.App();

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION || 'eu-west-2',
};

const pepStack = new AwsS8sOauthAndApiStack(app, 'AwsS8sOauthAndApiStack', {
  env,
  description: 'PEP stack: Auth_Server, Lambda_Authorizer, mock Appointments integration, DynamoDB, KMS, API Gateway',
});

const pcaStack = new NhsPcaEmulatorStack(app, 'NhsPcaEmulatorStack', {
  env,
  description: 'PCA Emulator stack: PCA_Lambda, KMS key, API Gateway',
  pepStack,
});

pcaStack.addDependency(pepStack);
