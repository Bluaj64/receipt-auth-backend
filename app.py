#!/usr/bin/env python3

import aws_cdk as cdk
from infra.auth_stack import AuthStack

app = cdk.App()

AuthStack(
    app,
    "ReceiptAuthStack",
    env=cdk.Environment(
        account="475783975001",
        region="us-east-2",
    ),
)

app.synth()