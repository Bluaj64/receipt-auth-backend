from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
)
from constructs import Construct
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_dynamodb as dynamodb

from aws_cdk.aws_apigatewayv2_alpha import (
    HttpApi,
    CorsHttpMethod,
    HttpMethod,
)
from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpLambdaIntegration


class AuthStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # Database Tables
        #Users
        users_table = dynamodb.Table(
            self,
            "UsersTable",
            table_name="ReceiptUsers",
            partition_key=dynamodb.Attribute(
                name="email",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )
        
        # Track Sessions
        sessions_table = dynamodb.Table(
            self,
            "SessionsTable",
            table_name="ReceiptSessions",
            partition_key=dynamodb.Attribute(
                name="token",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expiresAt",
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Lambdas
        # Auth Code:
        auth_lambda = _lambda.Function(
            self,
            "AuthLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambdas/auth"),
            timeout=Duration.seconds(10),
            environment={
                "USERS_TABLE": users_table.table_name,
                "SESSIONS_TABLE": sessions_table.table_name,
            },
        )

        # Perms
        users_table.grant_read_write_data(auth_lambda)
        sessions_table.grant_read_write_data(auth_lambda)

        # API G8WY
        # Lambda Integration
        auth_integration = HttpLambdaIntegration(
            "AuthLambdaIntegration",
            auth_lambda,
        )

        # Headers and CORS
        http_api = HttpApi(
            self,
            "ReceiptAuthApi",
            cors_preflight={
                "allow_origins": ["*"],
                "allow_methods": [
                    CorsHttpMethod.GET,
                    CorsHttpMethod.POST,
                    CorsHttpMethod.OPTIONS,
                ],
                "allow_headers": ["Content-Type"],
            },
        )

        # Routes
        http_api.add_routes(
            path="/signup",
            methods=[HttpMethod.POST],
            integration=auth_integration,
        )

        http_api.add_routes(
            path="/login",
            methods=[HttpMethod.POST],
            integration=auth_integration,
        )
        
        http_api.add_routes(
            path="/me",
            methods=[HttpMethod.GET],
            integration=auth_integration,
        )

        CfnOutput(
            self,
            "ApiUrl",
            value=http_api.api_endpoint,
        )